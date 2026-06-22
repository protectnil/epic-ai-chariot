/**
 * @epicai/chariot — Fast-path catalog/bundle/registry signature gate.
 *
 * Every fast-path read of `chariot-adapter-bundle.json` and its peers
 * goes through `verifyAndReadArtifact` so a tampered or unsigned bundle
 * cannot reach the dynamic `import(modulePath)` in toolHandlers.ts /
 * setup.ts. There is intentionally no opt-out env var; the slow path
 * (`AdapterCatalog` in src/engine/federation) is the only loader that
 * exposes a `verifySignature: false` override for dev/test.
 */

import { readFileSync, statSync } from 'node:fs';
import { verify as cryptoVerify, createPublicKey, type KeyObject } from 'node:crypto';
import { CHARIOT_CATALOG_PUBLIC_KEYS, type ChariotCatalogPublicKey } from './chariot-catalog-public.js';
import { MAX_CATALOG_BYTES } from '../federation/AdapterCatalog.js';
import { ABSOLUTE_MAX_ARTIFACT_BYTES, clampToAbsoluteMax } from './artifact-limits.js';
import type { LoggerInterface } from '../logger.js';

// Re-export ABSOLUTE_MAX_ARTIFACT_BYTES so downstream consumers that
// import it from this module continue to work after the central
// artifact-limits.ts policy table extraction.
export { ABSOLUTE_MAX_ARTIFACT_BYTES };

export type VerifyReason =
  | 'artifact-not-found'
  | 'signature-missing'
  | 'artifact-read-failed'
  | 'signature-read-failed'
  | 'oversize'
  | 'signature-verification-failed'
  | 'artifact-not-regular-file'
  | 'signature-not-regular-file'
  | 'signature-oversize';

/** Upper bound for a sidecar .sig file. An Ed25519 base64 signature is 88
 *  characters; even with a UTF-8 BOM + newlines + Windows CRLF padding the
 *  honest worst case is well under 256 bytes. 4 KiB is a comfortable cap
 *  that bounds peak memory if an attacker swaps the .sig for a multi-GB
 *  file at the expected path. */
const MAX_SIGNATURE_BYTES = 4 * 1024;

/**
 * Cache of parsed KeyObject per PEM string. Module-scoped so every
 * verifyAndReadArtifact call across the process reuses the parse.
 * The default CHARIOT_CATALOG_PUBLIC_KEYS entries get pre-warmed on
 * import below (fault-tolerant: a malformed entry is logged-and-
 * skipped rather than crashing the importer — same fail-soft semantics
 * the verify-time path has always had via try/catch around per-key
 * verify). The cache is LRU-bounded to KEY_CACHE_MAX_ENTRIES so a
 * caller passing many ad-hoc PEMs (eval suites, dynamic key paths)
 * cannot grow it without bound.
 */
const KEY_CACHE_MAX_ENTRIES = 256;
const keyCache = new Map<string, KeyObject>();

function getKeyObject(pem: string): KeyObject {
  const cached = keyCache.get(pem);
  if (cached) {
    // LRU touch: re-insert to push to end (Map iterates in insertion order).
    keyCache.delete(pem);
    keyCache.set(pem, cached);
    return cached;
  }
  const ko = createPublicKey(pem);
  if (keyCache.size >= KEY_CACHE_MAX_ENTRIES) {
    // Evict oldest (first-inserted) entry.
    const oldest = keyCache.keys().next().value;
    if (oldest !== undefined) keyCache.delete(oldest);
  }
  keyCache.set(pem, ko);
  return ko;
}

/**
 * Pre-warm the KeyObject cache for the given key list and return the
 * count of (accepted, skipped) entries. Exported so the eval suite can
 * exercise the REAL implementation against synthetic key lists instead
 * of testing an inline replica.
 *
 * FAULT-TOLERANT: a single malformed PEM — typo, env-substitution glitch
 * during rotation, deploy-time corruption — must NOT crash the module
 * import (every importer dies + no fallback). Bad entries are logged
 * to `warn` (defaults to a JSON line on stderr; the test suite can
 * inject a capture). The per-key try/catch at verify time covers the
 * same fall-through and continues to operate against remaining valid
 * keys. The warn line ensures operators see the rotation incident in
 * logs before the artifact-verify failure surfaces downstream.
 */
export function prewarmKeyCache(
  keys: ReadonlyArray<ChariotCatalogPublicKey>,
  warn: (event: { keyId: string; error: string }) => void = defaultPrewarmWarn,
): { accepted: number; skipped: number } {
  let accepted = 0;
  let skipped = 0;
  for (const k of keys) {
    try {
      getKeyObject(k.pem);
      accepted += 1;
    } catch (err) {
      skipped += 1;
      warn({ keyId: k.id, error: (err as Error)?.message ?? String(err) });
    }
  }
  return { accepted, skipped };
}

/**
 * Default pre-warm warn sink: a single JSON line on stderr. JSON so
 * downstream observability shippers / log parsers that consume the
 * chariot subprocess stderr as structured events do not have to special-
 * case the prewarm channel.
 */
function defaultPrewarmWarn(event: { keyId: string; error: string }): void {
  process.stderr.write(
    JSON.stringify({
      level: 'warn',
      component: 'chariot.verifyCatalogSignature',
      event: 'prewarm_malformed_pem',
      keyId: event.keyId,
      error: event.error,
    }) + '\n',
  );
}

// Module-load pre-warm: kick off the cache for the production-default
// key list so the first verifyAndReadArtifact call already finds parsed
// KeyObjects. Bad entries skip + log per prewarmKeyCache's contract.
prewarmKeyCache(CHARIOT_CATALOG_PUBLIC_KEYS);

export type VerifyArtifactResult =
  | { ok: true; bytes: Buffer; keyId: string }
  | { ok: false; reason: VerifyReason; detail?: string };

function readBytes(path: string):
  | { ok: true; bytes: Buffer }
  | { ok: false; enoent: boolean; detail?: string } {
  try {
    return { ok: true, bytes: readFileSync(path) };
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    return { ok: false, enoent: code === 'ENOENT', detail: code ?? String(err) };
  }
}

/**
 * Shared stat-precheck used by both the artifact and the sidecar .sig
 * paths. Returns failure if:
 *   - stat fails (mapped to per-path enoent vs read-failed reason)
 *   - the path is not a regular file (rejects /dev/zero, FIFO, socket,
 *     directory, symlink-to-special) — the size cap is meaningless for
 *     these because special files report size=0
 *   - the on-disk size exceeds the cap (bounds peak memory BEFORE the
 *     subsequent readFileSync would have allocated)
 */
type StatPrecheckReasonSet = Readonly<{
  notFound: VerifyReason;
  readFailed: VerifyReason;
  notRegularFile: VerifyReason;
  oversize: VerifyReason;
}>;

type StatPrecheckResult =
  | { ok: true; size: number }
  | { ok: false; reason: VerifyReason; detail: string };

function statPrecheck(
  path: string,
  maxBytes: number,
  reasons: StatPrecheckReasonSet,
): StatPrecheckResult {
  let st;
  try {
    st = statSync(path);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    return {
      ok: false,
      reason: code === 'ENOENT' ? reasons.notFound : reasons.readFailed,
      detail: code ?? String(err),
    };
  }
  if (!st.isFile()) {
    return {
      ok: false,
      reason: reasons.notRegularFile,
      detail: `not a regular file (mode=${st.mode.toString(8)})`,
    };
  }
  if (st.size > maxBytes) {
    return {
      ok: false,
      reason: reasons.oversize,
      detail: `${st.size}/${maxBytes}`,
    };
  }
  return { ok: true, size: st.size };
}

const ARTIFACT_REASONS: StatPrecheckReasonSet = {
  notFound: 'artifact-not-found',
  readFailed: 'artifact-read-failed',
  notRegularFile: 'artifact-not-regular-file',
  oversize: 'oversize',
};

const SIG_REASONS: StatPrecheckReasonSet = {
  notFound: 'signature-missing',
  readFailed: 'signature-read-failed',
  notRegularFile: 'signature-not-regular-file',
  oversize: 'signature-oversize',
};

/**
 * statPrecheck → readBytes → belt-and-braces post-read cap, with all
 * reason codes parameterized via the per-path StatPrecheckReasonSet.
 * Both the artifact and the .sig sidecar go through this helper so the
 * read pipeline cannot drift between the two — the round-4 .sig bypass
 * (E-A) and the round-5 .sig post-read TOCTOU (Quality) were the same
 * drift class, both now structurally precluded.
 */
function readWithCap(
  path: string,
  maxBytes: number,
  reasons: StatPrecheckReasonSet,
):
  | { ok: true; bytes: Buffer }
  | { ok: false; reason: VerifyReason; detail: string } {
  const pre = statPrecheck(path, maxBytes, reasons);
  if (!pre.ok) {
    return { ok: false, reason: pre.reason, detail: pre.detail };
  }
  const r = readBytes(path);
  if (!r.ok) {
    return {
      ok: false,
      reason: r.enoent ? reasons.notFound : reasons.readFailed,
      detail: r.detail ?? '',
    };
  }
  // Belt-and-braces: file grew between stat and read (TOCTOU). Same
  // defense on both artifact and .sig paths.
  if (r.bytes.length > maxBytes) {
    return { ok: false, reason: reasons.oversize, detail: `${r.bytes.length}/${maxBytes}` };
  }
  return { ok: true, bytes: r.bytes };
}

export function verifyAndReadArtifact(
  artifactPath: string,
  acceptedKeys: ReadonlyArray<ChariotCatalogPublicKey> = CHARIOT_CATALOG_PUBLIC_KEYS,
  maxBytes: number = MAX_CATALOG_BYTES,
): VerifyArtifactResult {
  // Process-wide ceiling: the per-call argument can lower the cap but
  // never raise it past ABSOLUTE_MAX_ARTIFACT_BYTES. clampToAbsoluteMax
  // also rejects NaN / Infinity / negative inputs (Math.min(NaN, x)
  // returns NaN, which would silently bypass the oversize comparison).
  const effectiveMax = clampToAbsoluteMax(maxBytes);

  // Single read pipeline for both the artifact and its .sig sidecar:
  // statPrecheck + readBytes + post-read cap, parameterized by reason
  // map. Round-4 added the artifact prechecks; round-5 mirrored them on
  // the .sig path AND added the post-read cap. Round-6 consolidated into
  // this helper so a future precheck addition cannot drift between paths.
  const artifact = readWithCap(artifactPath, effectiveMax, ARTIFACT_REASONS);
  if (!artifact.ok) {
    return { ok: false, reason: artifact.reason, detail: artifact.detail };
  }
  const sig = readWithCap(`${artifactPath}.sig`, MAX_SIGNATURE_BYTES, SIG_REASONS);
  if (!sig.ok) {
    return { ok: false, reason: sig.reason, detail: sig.detail };
  }
  // Strip every whitespace char (\r, \n, spaces, tabs) and the UTF-8 BOM
  // so .sig files written by Windows editors / pasted through clipboards
  // still decode cleanly. Plain `.trim()` only removes leading/trailing.
  const sigText = sig.bytes
    .toString('utf-8')
    .replace(/^\uFEFF/, '')
    .replace(/\s+/g, '');
  const sigBytes = Buffer.from(sigText, 'base64');
  for (const key of acceptedKeys) {
    try {
      // Look up the cached KeyObject for this PEM. Node's crypto otherwise
      // re-parses the PEM string into an ASN.1 KeyObject on every call.
      // With ≥3 signed artifacts loaded per boot × N keys, that's 3·N
      // PEM parses per boot — pure repeated work since the key set is
      // module-frozen. Cache miss falls back to parsing on the fly so
      // callers passing custom keys (test fixtures, eval suite) still
      // work without pre-registering.
      const keyObject = getKeyObject(key.pem);
      if (cryptoVerify(null, artifact.bytes, keyObject, sigBytes)) {
        return { ok: true, bytes: artifact.bytes, keyId: key.id };
      }
    } catch {
      /* try the next key */
    }
  }
  return {
    ok: false,
    reason: 'signature-verification-failed',
    detail: `tried ${acceptedKeys.length} key(s)`,
  };
}

/**
 * Verify-or-null convenience used by every fast-path catalog loader.
 * Returns verified bytes or null. Logs every failure mode EXCEPT
 * `artifact-not-found` — that one is the legitimate "no catalog
 * installed yet" state for a fresh install before the publisher has
 * run, and would generate alert noise on every wizard launch.
 */
export function verifiedReadOrNull(
  artifactPath: string,
  log: LoggerInterface,
  label: string,
  acceptedKeys: ReadonlyArray<ChariotCatalogPublicKey> = CHARIOT_CATALOG_PUBLIC_KEYS,
  maxBytes: number = MAX_CATALOG_BYTES,
): Buffer | null {
  const r = verifyAndReadArtifact(artifactPath, acceptedKeys, maxBytes);
  if (r.ok) return r.bytes;
  if (r.reason !== 'artifact-not-found') {
    log.error('catalog signature gate failed', {
      label,
      reason: r.reason,
      path: artifactPath,
      detail: r.detail,
    });
  }
  return null;
}
