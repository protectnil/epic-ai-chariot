/**
 * @epicai/chariot — Discovered-Adapter Signing Envelope
 *
 * Per-host Ed25519 keypair generated on first use (private 0600, public
 * 0644 in ~/.epic-ai/). Every discovered-adapter JSON is wrapped in
 * `{ payload, _signature, _signedBy, _adapterId, _signedAt }` so a tampered,
 * renamed, duplicated, or rolled-back file under
 * ~/.epic-ai/discovered-adapters/ is rejected at load time:
 *   - the signature covers { payload, adapterId, signedAt } — identity and
 *     freshness are INSIDE the signed bytes, so copying a validly-signed
 *     envelope under another filename or editing its timestamp breaks it;
 *   - the loader requires the filename stem to equal _adapterId;
 *   - a signed per-adapterId high-watermark of the newest accepted _signedAt
 *     (discovered-adapters.watermarks.json in ~/.epic-ai/, OUTSIDE the
 *     discovered-adapters/ dir) rejects restored older envelopes.
 *
 * The signing input is a canonical JSON serialization (lexicographic
 * object-key sort, undefined dropped, toJSON honored) so signer and verifier
 * produce byte-identical bytes across re-serialization.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
  type KeyObject,
} from 'node:crypto';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

// FIX (2026-09-30, release-blocking): this constant did NOT honor
// EPIC_AI_DIR_OVERRIDE, unlike src/cli/paths.ts's EPIC_AI_DIR
// (`process.env.EPIC_AI_DIR_OVERRIDE ?? join(homedir(), '.epic-ai')`) —
// the SAME env var, sandboxed-test-isolation pattern used throughout this
// codebase's own test suite. In production (no override set) both
// resolve identically to the real `~/.epic-ai`, so the discrepancy was
// invisible there. But ChariotState.ts's discovered-adapter overlay calls
// `loadVerifiedDiscoveredAdapters()` with NO arguments — relying on this
// default — so ANY test harness using EPIC_AI_DIR_OVERRIDE for isolation
// (as this repo's own tests do) silently read/verified discovered-adapter
// envelopes from the REAL ~/.epic-ai instead of the sandboxed one,
// making a correctly-signed, correctly-written test fixture invisible to
// loadAllAdapters()/loadChariotState() while `loadVerifiedDiscoveredAdapters(
// paths)` called with an EXPLICIT paths argument worked fine — confirmed
// by direct reproduction while building test/discovered-rest-adapter.mjs.
export const DEFAULT_EPIC_AI_DIR = process.env.EPIC_AI_DIR_OVERRIDE ?? join(homedir(), '.epic-ai');

export interface EnvelopePaths {
  epicAiDir: string;
  discoveredDir: string;
  privateKeyPath: string;
  publicKeyPath: string;
}

export function defaultEnvelopePaths(epicAiDir: string = DEFAULT_EPIC_AI_DIR): EnvelopePaths {
  return {
    epicAiDir,
    discoveredDir: join(epicAiDir, 'discovered-adapters'),
    privateKeyPath: join(epicAiDir, 'discovery-key.private.pem'),
    publicKeyPath: join(epicAiDir, 'discovery-key.public.pem'),
  };
}

/**
 * Path of the signed anti-rollback watermark index. Deliberately OUTSIDE
 * discovered-adapters/ so an attacker whose write access is limited to that
 * directory (the envelope threat model) cannot remove the high-watermarks.
 */
export function watermarkIndexPath(paths: EnvelopePaths = defaultEnvelopePaths()): string {
  return join(paths.epicAiDir, 'discovered-adapters.watermarks.json');
}

export interface SignedAdapterEnvelope {
  payload: Record<string, unknown>;
  _signature: string;
  _signedBy: string;
  /** Adapter identity bound inside the signed bytes (must equal payload.id and the filename stem). */
  _adapterId: string;
  /** ISO-8601 signing time bound inside the signed bytes (anti-rollback freshness). */
  _signedAt: string;
}

/**
 * Canonical JSON form used by both signer and verifier so the signed
 * bytes are stable across re-serialization. Sorts object keys
 * lexicographically, drops undefined values, and honors toJSON() (Date and
 * other toJSON-bearing instances) exactly as JSON.stringify does — without
 * this, a Date signed in-memory serialized as '{}' while the mandatory disk
 * round-trip produced its ISO string, so the signature could never verify.
 */
export function canonicalJson(value: unknown): string {
  if (value === undefined) return 'null';
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) {
    // Mirror JSON.stringify: array slots that are undefined OR sparse
    // (missing) serialize to null so signer/verifier byte-output stays
    // identical after a disk round-trip through JSON.parse(JSON.stringify).
    const parts: string[] = [];
    for (let i = 0; i < value.length; i++) {
      parts.push(canonicalJson(value[i]));
    }
    return '[' + parts.join(',') + ']';
  }
  // Mirror JSON.stringify's toJSON contract (Date → ISO string, etc.) so the
  // canonical form of a live object equals the canonical form of its
  // JSON.parse(JSON.stringify(...)) round-trip. Recursion covers nested cases.
  const toJSONFn = (value as { toJSON?: unknown }).toJSON;
  if (typeof toJSONFn === 'function') {
    return canonicalJson((toJSONFn as (key?: string) => unknown).call(value));
  }
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return '{' + entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',') + '}';
}

export function discoveryHostKeyId(publicPem: string): string {
  return createHash('sha256').update(publicPem).digest('hex').slice(0, 16);
}

export function ensureDiscoveryKeyPair(paths: EnvelopePaths = defaultEnvelopePaths()): { privateKey: KeyObject; publicPem: string } {
  mkdirSync(paths.epicAiDir, { recursive: true });
  const havePrivate = existsSync(paths.privateKeyPath);
  const havePublic = existsSync(paths.publicKeyPath);
  if (havePrivate && havePublic) {
    const stPriv = statSync(paths.privateKeyPath);
    if ((stPriv.mode & 0o077) !== 0) {
      try {
        chmodSync(paths.privateKeyPath, 0o600);
      } catch (err) {
        throw new Error(
          `discovery private key ${paths.privateKeyPath} has loose permissions (mode=${(stPriv.mode & 0o777).toString(8)}) and could not be tightened to 0600: ${(err as Error).message}`
        );
      }
    }
    const privatePem = readFileSync(paths.privateKeyPath, 'utf-8');
    const publicPem = readFileSync(paths.publicKeyPath, 'utf-8');
    return { privateKey: createPrivateKey(privatePem), publicPem };
  }
  if (havePrivate && !havePublic) {
    // Trust root intact — re-derive the public PEM from the private key
    // instead of regenerating the pair. The previous both-files-exist check
    // silently generated a NEW keypair here, rotating the trust root and
    // orphaning every previously signed envelope with no alarm.
    const privatePem = readFileSync(paths.privateKeyPath, 'utf-8');
    const privateKey = createPrivateKey(privatePem);
    const publicPem = createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }) as string;
    writeFileSync(paths.publicKeyPath, publicPem, { encoding: 'utf-8', mode: 0o644 });
    process.stderr.write(
      `chariot: discovery public key was missing; re-derived from the private key (keyId=${discoveryHostKeyId(publicPem)}) — trust root preserved\n`,
    );
    return { privateKey, publicPem };
  }
  if (!havePrivate && havePublic && process.env.CHARIOT_DISCOVERY_KEY_RESET !== 'true') {
    // Private key gone but envelopes were signed against the surviving
    // public key: regenerating here would silently orphan every previously
    // signed adapter. Fail loudly instead of rotating the trust root.
    throw new Error(
      `discovery private key missing at ${paths.privateKeyPath} while the public key exists at ${paths.publicKeyPath}; ` +
      'regenerating would silently invalidate every previously signed discovered adapter. ' +
      'Set CHARIOT_DISCOVERY_KEY_RESET=true (or remove both PEM files) to explicitly rotate the discovery trust root.',
    );
  }
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
  // 'wx' — refuse to clobber a key that appeared between the existence check
  // and the write (race/partial state must never overwrite a trust root).
  writeFileSync(paths.privateKeyPath, privatePem, { encoding: 'utf-8', mode: 0o600, flag: 'wx' });
  try {
    writeFileSync(paths.publicKeyPath, publicPem, { encoding: 'utf-8', mode: 0o644, flag: process.env.CHARIOT_DISCOVERY_KEY_RESET === 'true' ? 'w' : 'wx' });
  } catch (err) {
    throw new Error(`failed to write discovery public key ${paths.publicKeyPath}: ${(err as Error).message}`);
  }
  // Loud one-time notice: a fresh trust root means zero previously signed
  // envelopes will verify — visible, never silent.
  process.stderr.write(`chariot: generated new discovery keypair (keyId=${discoveryHostKeyId(publicPem)})\n`);
  return { privateKey, publicPem };
}

export function signDiscoveredAdapter(payload: Record<string, unknown>, paths: EnvelopePaths = defaultEnvelopePaths()): SignedAdapterEnvelope {
  const adapterId = payload['id'];
  if (typeof adapterId !== 'string' || adapterId.length === 0) {
    throw new Error('signDiscoveredAdapter: payload.id (non-empty string) is required — the signature binds the adapter identity');
  }
  const { privateKey, publicPem } = ensureDiscoveryKeyPair(paths);
  const signedAt = new Date().toISOString();
  // Identity + freshness are INSIDE the signed bytes: a validly-signed
  // envelope cannot be renamed to another adapter id or replayed with an
  // altered timestamp without breaking the signature.
  const canonical = Buffer.from(canonicalJson({ payload, adapterId, signedAt }), 'utf-8');
  const signature = cryptoSign(null, canonical, privateKey).toString('base64');
  return {
    payload,
    _signature: signature,
    _signedBy: discoveryHostKeyId(publicPem),
    _adapterId: adapterId,
    _signedAt: signedAt,
  };
}

export function verifyDiscoveredAdapter(
  envelope: unknown,
  paths: EnvelopePaths = defaultEnvelopePaths(),
  expectedAdapterId?: string,
): Record<string, unknown> {
  if (!envelope || typeof envelope !== 'object') {
    throw new Error('discovered-adapter envelope is not an object');
  }
  const env = envelope as { payload?: unknown; _signature?: unknown; _signedBy?: unknown; _adapterId?: unknown; _signedAt?: unknown };
  if (!env.payload || typeof env.payload !== 'object' || Array.isArray(env.payload)) {
    throw new Error('discovered-adapter envelope missing payload object');
  }
  if (typeof env._signature !== 'string' || env._signature.length === 0) {
    throw new Error('discovered-adapter envelope missing _signature');
  }
  if (typeof env._signedBy !== 'string' || env._signedBy.length === 0) {
    throw new Error('discovered-adapter envelope missing _signedBy');
  }
  if (typeof env._adapterId !== 'string' || env._adapterId.length === 0 || typeof env._signedAt !== 'string' || env._signedAt.length === 0) {
    throw new Error('discovered-adapter envelope missing _adapterId/_signedAt identity binding (legacy unbound envelope?) — re-run discovery to re-sign');
  }
  const payloadId = (env.payload as Record<string, unknown>)['id'];
  if (payloadId !== env._adapterId) {
    throw new Error(`discovered-adapter payload.id "${String(payloadId)}" does not match signed _adapterId "${env._adapterId}"`);
  }
  if (expectedAdapterId !== undefined && env._adapterId !== expectedAdapterId) {
    throw new Error(`discovered-adapter signed for id "${env._adapterId}" but expected "${expectedAdapterId}" (copied/renamed envelope?)`);
  }
  if (!existsSync(paths.publicKeyPath)) {
    throw new Error(`discovery public key not found at ${paths.publicKeyPath}; refusing to trust adapter`);
  }
  const publicPem = readFileSync(paths.publicKeyPath, 'utf-8');
  const expectedId = discoveryHostKeyId(publicPem);
  if (env._signedBy !== expectedId) {
    throw new Error(`discovered-adapter signed by ${env._signedBy} but host key is ${expectedId}; refusing to trust adapter`);
  }
  const publicKey = createPublicKey(publicPem);
  const canonical = Buffer.from(
    canonicalJson({ payload: env.payload, adapterId: env._adapterId, signedAt: env._signedAt }),
    'utf-8',
  );
  const sigBytes = Buffer.from(env._signature, 'base64');
  if (!cryptoVerify(null, canonical, publicKey, sigBytes)) {
    throw new Error('discovered-adapter signature did not verify against host public key');
  }
  return env.payload as Record<string, unknown>;
}

/** Structured result of a discovered-adapter directory load. */
export interface DiscoveredAdapterLoadResult {
  adapters: Array<Record<string, unknown>>;
  /**
   * Per-file rejections (tamper, rename, rollback, legacy format). Callers
   * MUST surface a non-empty list through their structured logger — the
   * previous stderr-only reporting made N tampered files indistinguishable
   * from a clean load.
   */
  rejected: Array<{ file: string; reason: string }>;
}

interface WatermarkIndexFile {
  watermarks: Record<string, string>;
  _signature: string;
  _signedBy: string;
}

/**
 * Load the signed per-adapterId high-watermark index. Missing file → empty
 * map (first use). A present-but-unverifiable index is a tamper alarm and
 * THROWS (fail closed — the caller aborts the whole discovered overlay
 * rather than accepting potentially rolled-back envelopes).
 */
function loadWatermarks(paths: EnvelopePaths): Record<string, string> {
  const idxPath = watermarkIndexPath(paths);
  if (!existsSync(idxPath)) return {};
  const parsed = JSON.parse(readFileSync(idxPath, 'utf-8')) as Partial<WatermarkIndexFile>;
  if (!parsed || typeof parsed !== 'object' || !parsed.watermarks || typeof parsed.watermarks !== 'object'
    || typeof parsed._signature !== 'string' || typeof parsed._signedBy !== 'string') {
    throw new Error(`watermark index ${idxPath} is malformed; refusing to load discovered adapters`);
  }
  if (!existsSync(paths.publicKeyPath)) {
    throw new Error(`discovery public key not found at ${paths.publicKeyPath}; cannot verify watermark index`);
  }
  const publicPem = readFileSync(paths.publicKeyPath, 'utf-8');
  if (parsed._signedBy !== discoveryHostKeyId(publicPem)) {
    throw new Error(`watermark index ${idxPath} signed by ${parsed._signedBy} but host key differs; refusing to load discovered adapters`);
  }
  const canonical = Buffer.from(canonicalJson(parsed.watermarks), 'utf-8');
  if (!cryptoVerify(null, canonical, createPublicKey(publicPem), Buffer.from(parsed._signature, 'base64'))) {
    throw new Error(`watermark index ${idxPath} signature did not verify; refusing to load discovered adapters`);
  }
  return parsed.watermarks as Record<string, string>;
}

/** Best-effort persist of the advanced watermarks (requires the host private key). */
function saveWatermarks(watermarks: Record<string, string>, paths: EnvelopePaths): void {
  try {
    const { privateKey, publicPem } = ensureDiscoveryKeyPair(paths);
    const signature = cryptoSign(null, Buffer.from(canonicalJson(watermarks), 'utf-8'), privateKey).toString('base64');
    const file: WatermarkIndexFile = { watermarks, _signature: signature, _signedBy: discoveryHostKeyId(publicPem) };
    writeFileSync(watermarkIndexPath(paths), JSON.stringify(file, null, 2), { encoding: 'utf-8', mode: 0o600 });
  } catch (err) {
    // Persisting the high-watermark is protective bookkeeping; failure to
    // advance it must not block a load that already verified everything.
    process.stderr.write(`chariot: could not persist discovered-adapter watermarks: ${(err as Error).message}\n`);
  }
}

export function loadVerifiedDiscoveredAdapters(paths: EnvelopePaths = defaultEnvelopePaths()): DiscoveredAdapterLoadResult {
  if (!existsSync(paths.discoveredDir)) return { adapters: [], rejected: [] };
  // Throws on a tampered index — deliberate fail-closed abort of the overlay.
  const watermarks = loadWatermarks(paths);
  const rejected: Array<{ file: string; reason: string }> = [];
  const newest = new Map<string, { payload: Record<string, unknown>; signedAt: string; file: string }>();
  for (const fname of readdirSync(paths.discoveredDir)) {
    if (!fname.endsWith('.json')) continue;
    const fpath = join(paths.discoveredDir, fname);
    try {
      const raw = readFileSync(fpath, 'utf-8');
      const parsed = JSON.parse(raw) as unknown;
      // Filename↔identity binding: the stem must equal the signed adapter id,
      // so one validly-signed envelope cannot be duplicated under other names.
      const expectedAdapterId = fname.slice(0, -'.json'.length);
      const payload = verifyDiscoveredAdapter(parsed, paths, expectedAdapterId);
      const signedAt = (parsed as { _signedAt: string })._signedAt;
      // Anti-rollback: reject envelopes older than the signed high-watermark.
      const watermark = watermarks[expectedAdapterId];
      if (watermark !== undefined && signedAt < watermark) {
        throw new Error(`envelope signedAt ${signedAt} is older than the accepted high-watermark ${watermark} (rollback?)`);
      }
      // Dedupe by adapterId keeping the newest signedAt (deterministic).
      const existing = newest.get(expectedAdapterId);
      if (!existing || signedAt > existing.signedAt) {
        newest.set(expectedAdapterId, { payload, signedAt, file: fpath });
      }
    } catch (err) {
      const reason = (err as Error).message;
      rejected.push({ file: fpath, reason });
      process.stderr.write(`chariot: rejecting ${fpath}: ${reason}\n`);
    }
  }
  // Advance and persist the high-watermarks for everything accepted.
  let advanced = false;
  for (const [adapterId, entry] of newest) {
    const prior = watermarks[adapterId];
    if (prior === undefined || entry.signedAt > prior) {
      watermarks[adapterId] = entry.signedAt;
      advanced = true;
    }
  }
  if (advanced) saveWatermarks(watermarks, paths);
  return { adapters: [...newest.values()].map((e) => e.payload), rejected };
}
