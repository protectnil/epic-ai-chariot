/**
 * @epicai/chariot — Offline kit installer (dogfood-ready 4.0 contract).
 *
 * A recipient-specific tarball (never the public npm package — see
 * scripts/refuse-kit-in-public.mjs) carries a `kit/` directory at the
 * package root:
 *
 *   kit/kit-manifest.json   { "version": 1, "files": { "<relpath>": "<sha256>" } }
 *   kit/models/...          dense / splade / reranker model files + manifest.json
 *   kit/edgeshard/catalog.edgeshard.sealed
 *   kit/edgeshard/catalog.edgeshard.sealed.ciphertext  (file-form ciphertext, CHARIOT §5.7)
 *   kit/lib/libonnxruntime.so*
 *   kit/chariot.license     licence envelope { jwt, renewal_secret, seal_secret? }
 *
 * The kit mirrors the default Epic AI dir layout. `installOfflineKit`:
 *   1. validates the manifest (version, relpaths, hash syntax) and the kit
 *      tree (no symlinks, no special files, no unlisted files, no missing
 *      listed files);
 *   2. verifies EVERY sha256 before anything is written — any failure
 *      installs nothing;
 *   3. installs the licence through the existing activateLicenseFromPath
 *      (signature / expiry / jti / epoch checks) — never a raw copy;
 *   4. copies every other file into the Epic AI dir mirroring its relative
 *      path (dirs it creates 0700, files 0600), per file via tmp + rename,
 *      re-hashing the bytes actually written;
 *   5. is idempotent: a destination file whose sha256 already matches is
 *      skipped.
 *
 * Every failure is a ChariotError (cli:wizard) with remediation, so the
 * wizard aborts through the central typed-error path.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import {
  chmodSync,
  constants as fsConstants,
  createReadStream,
  createWriteStream,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  unlinkSync,
} from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, posix, resolve, win32 } from 'node:path';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { fileURLToPath } from 'node:url';
import { ChariotError, fail } from './envelope.js';
import { activateLicenseFromPath, type ActivateOutcome } from '../license/activate.js';
import { licenseFilePath, verifyAndDecode } from '../license/loader.js';

const SURFACE = 'cli:wizard';

export const KIT_DIR_NAME = 'kit';
export const KIT_MANIFEST_NAME = 'kit-manifest.json';
export const KIT_LICENSE_RELPATH = 'chariot.license';

/** Artifact classes, keyed by the first relpath segment (licence by exact name). */
export type KitArtifactClass = 'models' | 'edgeshard' | 'onnxruntime' | 'license';

const CLASS_BY_TOP_SEGMENT: Readonly<Record<string, KitArtifactClass>> = {
  models: 'models',
  edgeshard: 'edgeshard',
  lib: 'onnxruntime',
};

const CLASS_ORDER: readonly KitArtifactClass[] = ['license', 'models', 'edgeshard', 'onnxruntime'];

const MODEL_SUBDIRS: ReadonlySet<string> = new Set(['dense', 'splade', 'reranker']);
/** The sealed descriptor and its file-reference ciphertext (CHARIOT §5.7:
 * "the default delivery names `catalog.edgeshard.sealed.ciphertext` beside
 * `catalog.edgeshard.sealed`"). Exactly these two names, nothing else. */
const EDGESHARD_KIT_RELPATHS: ReadonlySet<string> = new Set([
  'edgeshard/catalog.edgeshard.sealed',
  'edgeshard/catalog.edgeshard.sealed.ciphertext',
]);
const ORT_LIBRARY_RE = /^libonnxruntime\.so(\.[0-9]+)*$/;

const SHA256_HEX_RE = /^[0-9a-fA-F]{64}$/;

export interface KitClassSummary {
  cls: KitArtifactClass;
  /** Files written this run. */
  installed: number;
  /** Files whose destination already carried the expected sha256. */
  unchanged: number;
}

export type KitLicenseOutcome =
  | { kind: 'absent' }
  | { kind: 'activated'; companyId: string; expiresAtIso: string; writtenPath: string }
  | { kind: 'unchanged'; path: string }
  | { kind: 'kept-newer'; path: string };

export type OfflineKitSummary =
  | { present: false }
  | {
      present: true;
      classes: KitClassSummary[];
      license: KitLicenseOutcome;
    };

/** Minimal view of a verified licence the idempotency check needs. */
export interface KitLicenseClaims {
  companyId: string;
  expUnix: number;
}

export interface OfflineKitDeps {
  /** Install the licence at `sourcePath` (default: activateLicenseFromPath). */
  activateLicense: (sourcePath: string) => ActivateOutcome;
  /** Where the installed licence lives (default: licenseFilePath()). */
  installedLicensePath: string;
  /** Signature-verify a licence JWT (default: loader.verifyAndDecode). */
  verifyJwt: (jwt: string) => KitLicenseClaims | null;
}

export function defaultOfflineKitDeps(): OfflineKitDeps {
  return {
    activateLicense: (sourcePath) => activateLicenseFromPath(sourcePath),
    installedLicensePath: licenseFilePath(),
    verifyJwt: (jwt) => verifyAndDecode(jwt),
  };
}

/**
 * The installed package root — same derivation as src/cli/telemetry.ts:
 * src/cli -> package root, and dist/cli -> package root: same depth.
 */
export function defaultPackageRoot(): string {
  return resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
}

function kitError(code: string, cause: string, remediation: string[]): ChariotError {
  return new ChariotError(fail(SURFACE, code, {
    cause,
    human_message: `Offline kit not installed: ${cause}`,
    agent_message: `The offline kit under the package's kit/ directory was refused; nothing from it was installed. ${cause}`,
    remediation,
    must_not: ['copy kit files into the Epic AI directory by hand', 'treat the kit as installed'],
  }));
}

const REMEDIATE_REISSUE = 'Ask your Epic AI contact to re-issue the offline kit tarball, then reinstall it (npm install <kit tarball>) and re-run `chariot`.';
const REMEDIATE_UNTOUCHED = 'Do not edit files under the package kit/ directory; the manifest pins every byte.';

/**
 * Validate one manifest key. Returns its posix segments, or a reason string.
 * Rejects: empty, NUL, backslash, absolute (posix/win32/drive), empty / `.` /
 * `..` segments, the manifest itself, and anything outside the four
 * contract artifact locations (so a kit can never write config, credentials
 * or state into the Epic AI dir).
 */
export function validateKitRelPath(rel: string): { ok: true; segments: string[]; cls: KitArtifactClass } | { ok: false; reason: string } {
  if (rel.length === 0) return { ok: false, reason: 'empty path' };
  if (rel.includes('\0')) return { ok: false, reason: 'NUL byte in path' };
  if (rel.includes('\\')) return { ok: false, reason: 'backslash in path' };
  if (posix.isAbsolute(rel) || win32.isAbsolute(rel) || isAbsolute(rel) || /^[A-Za-z]:/.test(rel)) {
    return { ok: false, reason: 'absolute path' };
  }
  const segments = rel.split('/');
  for (const seg of segments) {
    if (seg === '' || seg === '.' || seg === '..') {
      return { ok: false, reason: `illegal path segment ${JSON.stringify(seg)}` };
    }
  }
  if (rel === KIT_MANIFEST_NAME) return { ok: false, reason: 'the manifest cannot list itself' };
  if (rel === KIT_LICENSE_RELPATH) return { ok: true, segments, cls: 'license' };
  const cls = CLASS_BY_TOP_SEGMENT[segments[0]!];
  // Exactly the §17.2a layout: models/{dense,splade,reranker}/<file>,
  // edgeshard/catalog.edgeshard.sealed (+ its file-form ciphertext
  // edgeshard/catalog.edgeshard.sealed.ciphertext, CHARIOT §5.7 envelope
  // fields AMENDED 2026-10-14), lib/libonnxruntime.so*.
  const inLayout =
    (cls === 'models' && segments.length === 3 && MODEL_SUBDIRS.has(segments[1]!)) ||
    (cls === 'edgeshard' && EDGESHARD_KIT_RELPATHS.has(rel)) ||
    (cls === 'onnxruntime' && segments.length === 2 && ORT_LIBRARY_RE.test(segments[1]!));
  if (!inLayout) {
    return {
      ok: false,
      reason: 'outside the kit layout (models/{dense,splade,reranker}/<file>, edgeshard/catalog.edgeshard.sealed, edgeshard/catalog.edgeshard.sealed.ciphertext, lib/libonnxruntime.so*, chariot.license)',
    };
  }
  return { ok: true, segments, cls: cls! };
}

interface KitEntry {
  rel: string;
  segments: string[];
  cls: KitArtifactClass;
  sha256: string;
  src: string;
}

function parseManifest(kitDir: string): KitEntry[] {
  const manifestPath = join(kitDir, KIT_MANIFEST_NAME);
  let st;
  try {
    st = lstatSync(manifestPath);
  } catch {
    throw kitError('OFFLINE_KIT_INVALID', `kit/${KIT_MANIFEST_NAME} is missing.`, [REMEDIATE_REISSUE]);
  }
  if (!st.isFile()) {
    throw kitError('OFFLINE_KIT_INVALID', `kit/${KIT_MANIFEST_NAME} is not a regular file.`, [REMEDIATE_REISSUE]);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(manifestPath, 'utf-8'));
  } catch {
    throw kitError('OFFLINE_KIT_INVALID', `kit/${KIT_MANIFEST_NAME} is not valid JSON.`, [REMEDIATE_REISSUE]);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw kitError('OFFLINE_KIT_INVALID', `kit/${KIT_MANIFEST_NAME} is not a JSON object.`, [REMEDIATE_REISSUE]);
  }
  const m = parsed as { version?: unknown; files?: unknown };
  if (m.version !== 1) {
    throw kitError('OFFLINE_KIT_INVALID', `kit/${KIT_MANIFEST_NAME} has unsupported version ${JSON.stringify(m.version)} (expected 1).`, [
      'Update Chariot to a build that supports this kit version, or ask for a version-1 kit.',
    ]);
  }
  if (!m.files || typeof m.files !== 'object' || Array.isArray(m.files)) {
    throw kitError('OFFLINE_KIT_INVALID', `kit/${KIT_MANIFEST_NAME} has no "files" object.`, [REMEDIATE_REISSUE]);
  }
  const files = m.files as Record<string, unknown>;
  const keys = Object.keys(files);
  if (keys.length === 0) {
    throw kitError('OFFLINE_KIT_INVALID', `kit/${KIT_MANIFEST_NAME} lists no files.`, [REMEDIATE_REISSUE]);
  }
  const entries: KitEntry[] = [];
  const foldedSeen = new Map<string, string>();
  for (const rel of keys) {
    const v = validateKitRelPath(rel);
    if (!v.ok) {
      throw kitError('OFFLINE_KIT_INVALID', `kit/${KIT_MANIFEST_NAME} lists ${JSON.stringify(rel)}: ${v.reason}.`, [REMEDIATE_REISSUE]);
    }
    // Case-insensitive filesystems (macOS, Windows) would collapse two keys
    // onto one destination; refuse rather than install whichever lands last.
    const folded = rel.toLowerCase();
    const prior = foldedSeen.get(folded);
    if (prior !== undefined) {
      throw kitError('OFFLINE_KIT_INVALID', `kit/${KIT_MANIFEST_NAME} lists ${JSON.stringify(prior)} and ${JSON.stringify(rel)}, which collide on a case-insensitive filesystem.`, [REMEDIATE_REISSUE]);
    }
    foldedSeen.set(folded, rel);
    const hash = files[rel];
    if (typeof hash !== 'string' || !SHA256_HEX_RE.test(hash)) {
      throw kitError('OFFLINE_KIT_INVALID', `kit/${KIT_MANIFEST_NAME} entry ${JSON.stringify(rel)} does not carry a 64-hex-digit sha256.`, [REMEDIATE_REISSUE]);
    }
    entries.push({ rel, segments: v.segments, cls: v.cls, sha256: hash.toLowerCase(), src: join(kitDir, ...v.segments) });
  }
  return entries;
}

/**
 * Walk the kit tree WITHOUT following links. Every regular file other than
 * the manifest must be listed; any symlink or special file anywhere refuses
 * the kit; every listed file must exist as a regular file.
 */
function checkKitTree(kitDir: string, entries: readonly KitEntry[]): void {
  const listed = new Set(entries.map(e => e.rel));
  const found = new Set<string>();
  const walk = (absDir: string, relDir: string): void => {
    for (const d of readdirSync(absDir, { withFileTypes: true })) {
      const rel = relDir === '' ? d.name : `${relDir}/${d.name}`;
      if (d.isSymbolicLink()) {
        throw kitError('OFFLINE_KIT_INVALID', `kit/${rel} is a symbolic link; the kit must contain regular files only.`, [REMEDIATE_UNTOUCHED, REMEDIATE_REISSUE]);
      }
      if (d.isDirectory()) {
        walk(join(absDir, d.name), rel);
        continue;
      }
      if (!d.isFile()) {
        throw kitError('OFFLINE_KIT_INVALID', `kit/${rel} is not a regular file.`, [REMEDIATE_UNTOUCHED, REMEDIATE_REISSUE]);
      }
      if (rel === KIT_MANIFEST_NAME) continue;
      if (!listed.has(rel)) {
        throw kitError('OFFLINE_KIT_INVALID', `kit/${rel} is not listed in kit/${KIT_MANIFEST_NAME}.`, [REMEDIATE_UNTOUCHED, REMEDIATE_REISSUE]);
      }
      found.add(rel);
    }
  };
  walk(kitDir, '');
  for (const e of entries) {
    if (!found.has(e.rel)) {
      throw kitError('OFFLINE_KIT_INVALID', `kit/${e.rel} is listed in kit/${KIT_MANIFEST_NAME} but missing from the kit.`, [REMEDIATE_REISSUE]);
    }
  }
}

// O_NOFOLLOW is POSIX-only; 0 on platforms without it (the tree walk above
// has already refused every symlink).
const O_NOFOLLOW = (fsConstants as { O_NOFOLLOW?: number }).O_NOFOLLOW ?? 0;

async function sha256File(path: string, noFollow: boolean): Promise<string> {
  const hash = createHash('sha256');
  const fd = openSync(path, fsConstants.O_RDONLY | (noFollow ? O_NOFOLLOW : 0));
  for await (const chunk of createReadStream(path, { fd, autoClose: true })) {
    hash.update(chunk as Buffer);
  }
  return hash.digest('hex');
}

/** Create each missing directory component under `root` as 0700. */
function ensurePrivateDirs(root: string, segments: readonly string[]): void {
  let cur = root;
  const parts = ['', ...segments];
  for (const seg of parts) {
    cur = seg === '' ? cur : join(cur, seg);
    if (!existsSync(cur)) {
      mkdirSync(cur, { mode: 0o700 });
      chmodSync(cur, 0o700);
    }
  }
}

/** Copy src → dest via a private tmp file + rename, hashing the bytes written. */
async function copyVerifiedAtomic(entry: KitEntry, dest: string): Promise<void> {
  const tmp = `${dest}.kit-tmp.${process.pid}.${randomBytes(6).toString('hex')}`;
  const hash = createHash('sha256');
  const hasher = new Transform({
    transform(chunk, _enc, cb) {
      hash.update(chunk as Buffer);
      cb(null, chunk);
    },
  });
  try {
    const srcFd = openSync(entry.src, fsConstants.O_RDONLY | O_NOFOLLOW);
    await pipeline(
      createReadStream(entry.src, { fd: srcFd, autoClose: true }),
      hasher,
      createWriteStream(tmp, { flags: 'wx', mode: 0o600 }),
    );
    const got = hash.digest('hex');
    if (got !== entry.sha256) {
      throw kitError('OFFLINE_KIT_INVALID', `kit/${entry.rel} changed while it was being installed (sha256 ${got}, manifest ${entry.sha256}).`, [REMEDIATE_UNTOUCHED, 'Re-run `chariot`.']);
    }
    chmodSync(tmp, 0o600);
    renameSync(tmp, dest);
  } catch (err) {
    try { unlinkSync(tmp); } catch { /* tmp may not exist */ }
    if (err instanceof ChariotError) throw err;
    throw kitError('OFFLINE_KIT_INSTALL_FAILED', `could not write ${dest}: ${err instanceof Error ? err.message : String(err)}`, [
      'Check that the Epic AI directory is writable by this user and has free space, then re-run `chariot`.',
    ]);
  }
}

interface LicenseEnvelopeView { jwt: string; seal_secret?: unknown }

function readEnvelopeView(path: string): LicenseEnvelopeView | null {
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf-8')) as { jwt?: unknown; seal_secret?: unknown };
    if (!parsed || typeof parsed !== 'object' || typeof parsed.jwt !== 'string' || parsed.jwt.length === 0) return null;
    return { jwt: parsed.jwt, seal_secret: parsed.seal_secret };
  } catch {
    return null;
  }
}

/**
 * Licence step. Skips activation when the installed licence is the same
 * licence (same JWT and same seal_secret), or is a verified licence for the
 * same company that expires LATER than the kit's (a renewal since the kit
 * was cut — re-running the wizard must never downgrade it). Otherwise the
 * kit licence goes through activateLicenseFromPath.
 */
function installKitLicense(entry: KitEntry, deps: OfflineKitDeps): KitLicenseOutcome {
  const kitView = readEnvelopeView(entry.src);
  const installedPath = deps.installedLicensePath;
  const installedView = existsSync(installedPath) ? readEnvelopeView(installedPath) : null;
  if (kitView && installedView) {
    if (installedView.jwt === kitView.jwt && installedView.seal_secret === kitView.seal_secret) {
      return { kind: 'unchanged', path: installedPath };
    }
    const kitClaims = deps.verifyJwt(kitView.jwt);
    const installedClaims = deps.verifyJwt(installedView.jwt);
    if (kitClaims && installedClaims
      && installedClaims.companyId === kitClaims.companyId
      && installedClaims.expUnix > kitClaims.expUnix) {
      return { kind: 'kept-newer', path: installedPath };
    }
  }
  const outcome = deps.activateLicense(entry.src);
  if (!outcome.ok) {
    throw kitError('OFFLINE_KIT_LICENSE_REJECTED', `kit/${KIT_LICENSE_RELPATH} was refused (${outcome.reason}): ${outcome.message}`, [
      REMEDIATE_REISSUE,
      'If you already hold a current licence file, activate it with `chariot license activate <path>`.',
    ]);
  }
  // A kit is cut for one recipient: its licence must carry a usable seal
  // secret, or the kit's sealed shard can never be opened.
  if (outcome.sealSecretWarning) {
    throw kitError('OFFLINE_KIT_LICENSE_REJECTED', `kit/${KIT_LICENSE_RELPATH} carries an unusable seal_secret: ${outcome.sealSecretWarning}`, [REMEDIATE_REISSUE]);
  }
  return { kind: 'activated', companyId: outcome.claims.companyId, expiresAtIso: outcome.claims.expiresAtIso, writtenPath: outcome.writtenPath };
}

/**
 * Install the offline kit from `<packageRoot>/kit` into `epicAiDir`.
 * Absent `kit/` → `{ present: false }` and nothing happens.
 */
export async function installOfflineKit(
  packageRoot: string,
  epicAiDir: string,
  deps: OfflineKitDeps = defaultOfflineKitDeps(),
): Promise<OfflineKitSummary> {
  const kitDir = join(packageRoot, KIT_DIR_NAME);
  let kitStat;
  try {
    kitStat = lstatSync(kitDir);
  } catch {
    return { present: false };
  }
  if (!kitStat.isDirectory()) {
    throw kitError('OFFLINE_KIT_INVALID', `${kitDir} exists but is not a directory (a symbolic link or file is refused).`, [REMEDIATE_REISSUE]);
  }

  // Phase 1 — validate everything; write nothing.
  const entries = parseManifest(kitDir);
  checkKitTree(kitDir, entries);
  for (const e of entries) {
    let got: string;
    try {
      got = await sha256File(e.src, true);
    } catch (err) {
      throw kitError('OFFLINE_KIT_INVALID', `kit/${e.rel} could not be read: ${err instanceof Error ? err.message : String(err)}`, [REMEDIATE_REISSUE]);
    }
    if (got !== e.sha256) {
      throw kitError('OFFLINE_KIT_INVALID', `kit/${e.rel} sha256 ${got} does not match the manifest (${e.sha256}).`, [REMEDIATE_UNTOUCHED, REMEDIATE_REISSUE]);
    }
  }

  // Phase 2 — plan: decide per file whether it is already installed. Reads
  // only; a destination occupied by a directory refuses the kit here.
  const counts = new Map<KitArtifactClass, KitClassSummary>();
  const toInstall: Array<{ entry: KitEntry; dest: string }> = [];
  const unchangedDests: string[] = [];
  for (const e of entries) {
    if (e.cls === 'license') continue;
    const summary = counts.get(e.cls) ?? { cls: e.cls, installed: 0, unchanged: 0 };
    counts.set(e.cls, summary);
    const dest = join(epicAiDir, ...e.segments);
    if (existsSync(dest)) {
      if (statSync(dest).isDirectory()) {
        throw kitError('OFFLINE_KIT_INSTALL_FAILED', `${dest} is a directory; the kit needs to install a file there.`, [
          `Move ${dest} aside, then re-run \`chariot\`.`,
        ]);
      }
      let current: string | null = null;
      try { current = await sha256File(dest, false); } catch { current = null; }
      if (current === e.sha256) {
        unchangedDests.push(dest);
        summary.unchanged++;
        continue;
      }
    }
    toInstall.push({ entry: e, dest });
    summary.installed++;
  }

  // Phase 3 — stage every byte that will be installed (the licence included)
  // into one private directory inside the Epic AI dir, re-hashing as it is
  // copied. A digest that changed since Phase 1, or any write failure,
  // removes the staging directory and leaves the Epic AI dir as it was
  // (CHARIOT §17.2a: a listed digest mismatch installs nothing).
  const createdEpicAiDir = !existsSync(epicAiDir);
  let staging: string;
  try {
    mkdirSync(epicAiDir, { recursive: true, mode: 0o700 });
    staging = mkdtempSync(join(epicAiDir, '.kit-staging-'));
  } catch (err) {
    throw kitError('OFFLINE_KIT_INSTALL_FAILED', `could not prepare ${epicAiDir}: ${err instanceof Error ? err.message : String(err)}`, [
      'Check that the Epic AI directory and its parent exist and are writable by this user, then re-run `chariot`.',
    ]);
  }
  const discardStaging = (): void => {
    rmSync(staging, { recursive: true, force: true });
    if (createdEpicAiDir) rmSync(epicAiDir, { recursive: true, force: true });
  };
  const staged: Array<{ tmp: string; dest: string; entry: KitEntry }> = [];
  let license: KitLicenseOutcome = { kind: 'absent' };
  try {
    for (const [i, item] of toInstall.entries()) {
      const tmp = join(staging, String(i));
      await copyVerifiedAtomic(item.entry, tmp);
      staged.push({ tmp, dest: item.dest, entry: item.entry });
    }
    const licenseEntry = entries.find(e => e.cls === 'license');
    if (licenseEntry) {
      // The licence reaches the Epic AI dir only through activation
      // (§17.2a): its re-hashed copy is staged in a private directory
      // OUTSIDE the Epic AI dir and removed afterwards. Activation verifies
      // it before writing; a refusal leaves every file uninstalled.
      const licenseStaging = mkdtempSync(join(tmpdir(), 'chariot-kit-licence-'));
      try {
        const stagedLicense = join(licenseStaging, 'license');
        await copyVerifiedAtomic(licenseEntry, stagedLicense);
        license = installKitLicense({ ...licenseEntry, src: stagedLicense }, deps);
      } finally {
        rmSync(licenseStaging, { recursive: true, force: true });
      }
    }
  } catch (err) {
    discardStaging();
    throw err;
  }

  // Phase 4 — publish: rename each verified staged file into place (same
  // filesystem), then enforce 0600 on files that were already installed.
  try {
    for (const s of staged) {
      ensurePrivateDirs(epicAiDir, s.entry.segments.slice(0, -1));
      renameSync(s.tmp, s.dest);
    }
    // A skipped file is left untouched unless its mode is not 0600 (§17.2a:
    // re-runs change nothing; every installed non-licence file is 0600).
    for (const dest of unchangedDests) {
      if ((statSync(dest).mode & 0o777) !== 0o600) chmodSync(dest, 0o600);
    }
  } catch (err) {
    throw kitError('OFFLINE_KIT_INSTALL_FAILED', `could not install a verified kit file: ${err instanceof Error ? err.message : String(err)}`, [
      'Check that the Epic AI directory is writable by this user and has free space, then re-run `chariot`.',
    ]);
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }

  const classes = CLASS_ORDER
    .filter(c => c !== 'license' && counts.has(c))
    .map(c => counts.get(c)!);
  return { present: true, classes, license };
}

const CLASS_LABEL: Readonly<Record<KitArtifactClass, string>> = {
  models: 'retrieval models',
  edgeshard: 'sealed catalog shard',
  onnxruntime: 'ONNX Runtime library',
  license: 'licence',
};

/** One plain line per artifact class (empty when no kit is present). */
export function formatOfflineKitSummary(summary: OfflineKitSummary): string[] {
  if (!summary.present) return [];
  const lines: string[] = [];
  switch (summary.license.kind) {
    case 'activated':
      lines.push(`Offline kit: ${CLASS_LABEL.license} activated for ${summary.license.companyId} (expires ${summary.license.expiresAtIso})`);
      break;
    case 'unchanged':
      lines.push(`Offline kit: ${CLASS_LABEL.license} already installed`);
      break;
    case 'kept-newer':
      lines.push(`Offline kit: ${CLASS_LABEL.license} kept (installed licence is newer than the kit's)`);
      break;
    case 'absent':
      break;
  }
  for (const c of summary.classes) {
    const total = c.installed + c.unchanged;
    const files = `${total} file${total === 1 ? '' : 's'}`;
    lines.push(c.installed === 0
      ? `Offline kit: ${CLASS_LABEL[c.cls]} already installed (${files})`
      : `Offline kit: ${CLASS_LABEL[c.cls]} installed (${files}, ${c.installed} written)`);
  }
  return lines;
}
