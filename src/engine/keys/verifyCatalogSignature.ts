/**
 * @epicai/chariot — Fast-path catalog/bundle/registry signature gate.
 *
 * Every fast-path read of `chariot-adapter-bundle.json` and its peers
 * goes through `verifyAndReadArtifact` so a tampered or unsigned bundle
 * cannot reach the dynamic `import(modulePath)` in toolHandlers.ts /
 * setup.ts. There is intentionally no opt-out env var; the slow path
 * (`AdapterCatalog` in src/engine/federation) is the only loader that
 * exposes a `verifySignature: false` override for dev/test.
 *
 * CHARIOT-SPEC.md:525 ("Trust anchor", §5.7, CH-52), verbatim: "The Ed25519
 * verifying key SHALL be pinned to the compiled-in accepted key set
 * (`native/src/license.rs::ACCEPTED_PUBLIC_KEYS_PEM`). A caller-supplied
 * key outside that rotation set SHALL be rejected, so neither a caller nor
 * an attacker controlling the caller's configuration can substitute a
 * signing key." That clause's literal subject is the native sealed-EdgeShard
 * license verifier, a different Ed25519 key set than this module's
 * (`CHARIOT_CATALOG_PUBLIC_KEYS`, the catalog/bundle signing key, embedded
 * per CHARIOT-SPEC.md:355-357 §5.1: "Verification uses Node's
 * `crypto.verify(null, bytes, publicKeyPem, signature)`. The public key is
 * embedded at `src/engine/keys/chariot-catalog-public.ts`."). §5.1 does not
 * itself restate the no-caller-override sentence — this module applies the
 * SAME trust-anchor principle to its own pinned key by construction below:
 * every exported verifier in this file INTERSECTS any caller-supplied
 * `acceptedKeys` against the compiled-in `CHARIOT_CATALOG_PUBLIC_KEYS`
 * before ever attempting a signature check, so a key outside that rotation
 * set is never used, and a caller-supplied set with no member in the
 * rotation set fails closed with an explicit, distinct reason rather than
 * silently substituting an unpinned key or degrading to
 * "signature-verification-failed" (which would misattribute a config error
 * to a tamper finding).
 *
 * FPS §7.2.6 consumer lockstep (FABRIQUE-PRODUCT-SPEC-MAY-2026.md:712),
 * verbatim: "Adopting §7.2.3 changes the signed object from the prior
 * full-bundle-bytes model; the manifest MUST carry `signingPayloadVersion`,
 * and the consumer selects its verify path by that version (old full-bytes
 * vs new compact-payload), gated on the monotonic `epoch` anti-rollback ...
 * a single version-selected branch in the one Chariot artifact — NOT a
 * per-backend or per-cloud fork." `verifyAndReadArtifact` implements that
 * single branch for `chariot-adapter-bundle.json` (the only artifact that
 * carries the FPS §7.2.2 Merkle-leaf envelope): absent
 * `manifest.signingPayloadVersion` keeps the existing full-bytes
 * `crypto.verify(null, bytes, key, sig)` path unchanged; `=== 1` recomputes
 * the FPS §7.2.2 Merkle root and the FPS §7.2.3 compact payload
 * (`canonicalize/merkle.ts`, ported verbatim from the upstream materializer)
 * and verifies the signature over THAT instead; any other value fails
 * closed before a signature is ever attempted. The `epoch`
 * anti-rollback (CHARIOT-SPEC.md §5.6) lives downstream of this module (in
 * `ChariotState.ts`'s `wireRetrievalForState`/`wireHybridRetrieval`, invoked
 * only after this function returns `ok: true`) and is untouched by either
 * branch — it fires unconditionally on whichever path admitted the bundle.
 *
 * MIGRATION FACTS (stated verbatim so the sequencing risk is not silent):
 * as of this change, every materialized bundle already stamps
 * `manifest.signingPayloadVersion = 1`, but the primary `.sig` for a
 * bundle produced by a not-yet-updated producer still covers the FULL
 * bundle bytes, not the compact payload — such a bundle correctly FAILS
 * CLOSED under the `=== 1` branch here. This is by design, not a defect:
 * FPS §7.2.6 requires the paired producer change (flip the primary
 * signature to the compact payload) and this consumer verifier to land in
 * the SAME migration window, and the operator re-materializes the live
 * catalog against the updated producer before cutting a release that
 * ships this file. A rejection here for a pre-cutover bundle means
 * "re-materialize", not "this code is wrong".
 */

import { readFileSync, statSync } from 'node:fs';
import { verify as cryptoVerify, createPublicKey, createHash, type KeyObject } from 'node:crypto';
import { CHARIOT_CATALOG_PUBLIC_KEYS, type ChariotCatalogPublicKey } from './chariot-catalog-public.js';
import { canonicalize } from './canonicalize.js';
import { computeMerkleRoot, type MerkleLeafInput } from './merkle.js';
// NOTE: this file intentionally does NOT import from
// `../federation/AdapterCatalog.js` (it used to, for `MAX_CATALOG_BYTES`,
// which is just `ARTIFACT_LIMITS.catalog` re-exported). Read the limit
// directly from `artifact-limits.ts` instead — `AdapterCatalog.ts` now
// imports `intersectWithRotationSet` FROM this file (CHARIOT-SPEC.md:383,
// :523), so importing back from `AdapterCatalog.js` here would create an
// ESM import cycle between the two modules.
import { ABSOLUTE_MAX_ARTIFACT_BYTES, ARTIFACT_LIMITS, clampToAbsoluteMax } from './artifact-limits.js';
/** Same value as `AdapterCatalog.ts`'s `MAX_CATALOG_BYTES` (both read
 *  `ARTIFACT_LIMITS.catalog`) — kept as a local alias so the diff against
 *  every existing default-parameter call site below stays minimal. */
const MAX_CATALOG_BYTES = ARTIFACT_LIMITS.catalog;
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
  // CHARIOT-SPEC.md:525 trust-anchor principle (see module docstring): every
  // entry of a caller-supplied `acceptedKeys` was outside the compiled-in
  // `CHARIOT_CATALOG_PUBLIC_KEYS` rotation set — none was ever used to
  // attempt a signature check. Distinct from `signature-verification-failed`
  // (which means a TRUSTED key tried and did not match) so operators and
  // tests can tell "wrong/no key in the accepted set" from "tampered bytes".
  | 'accepted-keys-outside-rotation-set'
  | 'signature-oversize'
  // FPS §7.2.6 consumer lockstep, chariot-adapter-bundle.json only. The
  // artifact's own manifest.signingPayloadVersion is present but is not the
  // one supported value (integer 1) — e.g. 0, 2, a string, or a
  // non-integer. Distinct from 'signature-verification-failed' because no
  // signature attempt was ever made: the format itself is unrecognized.
  | 'signing-payload-version-invalid'
  // FPS §7.2.2/§7.2.3 — manifest.signingPayloadVersion === 1 but a field the
  // compact-payload recomputation depends on (manifest.merkleRoot,
  // bundle.epoch, bundle.catalogVersion, or a catalog[]/registry[] entry's
  // id/metadata.publishHash) is missing or the wrong type. Fails closed
  // before any Merkle recomputation or signature attempt.
  | 'compact-payload-malformed'
  // FPS §7.2.2 — catalog[] ∪ registry[] produced zero Merkle leaves. A
  // zero-record bundle is a fail-closed release error on the producer side;
  // the consumer refuses to admit one regardless of what merkleRoot/
  // signature it carries.
  | 'compact-payload-empty-leaf-set'
  // FPS §7.2.3 — "The serialized payload MUST be `< 4096` bytes". Strict
  // `<`; a payload of exactly 4096 bytes or more is rejected before any
  // signature attempt.
  | 'compact-payload-oversize'
  // FPS §7.2.2 — the Merkle root recomputed from catalog[]/registry[] does
  // not match the claimed manifest.merkleRoot. Any single record's bytes
  // changing (including a forged manifest.merkleRoot that does not match
  // the records actually shipped) is caught here, before a signature is
  // ever attempted over the (attacker-chosen) claimed root.
  | 'compact-payload-merkle-root-mismatch';

/** Upper bound for a sidecar .sig file. An Ed25519 base64 signature is 88
 *  characters; even with a UTF-8 BOM + newlines + Windows CRLF padding the
 *  honest worst case is well under 256 bytes. 4 KiB is a comfortable cap
 *  that bounds peak memory if an attacker swaps the .sig for a multi-GB
 *  file at the expected path. */
const MAX_SIGNATURE_BYTES = 4 * 1024;

/** FPS §7.2.3, verbatim: "The serialized payload MUST be `< 4096` bytes
 *  (asserted at sign time)." Strict `<`, not `<=` — matches the producer's
 *  own constant (`materializer/signing-payload.ts`
 *  `MAX_COMPACT_SIGNING_PAYLOAD_BYTES`). */
const MAX_COMPACT_SIGNING_PAYLOAD_BYTES = 4096;

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

/**
 * CHARIOT-SPEC.md:525 trust-anchor principle (module docstring above) —
 * the SINGLE choke point every exported verifier in this file routes a
 * caller-supplied `acceptedKeys` through before it is ever used to attempt
 * a signature check. Returns only the entries of `acceptedKeys` that are
 * ALSO present (by exact `pem` match — the PEM bytes ARE the key identity;
 * `id` is a label only) in the compiled-in `CHARIOT_CATALOG_PUBLIC_KEYS`
 * rotation set. A key not in that set is never included in the result and
 * therefore never reaches `cryptoVerify` — "rejected" in the clause's
 * sense, not merely "tried and failed". Exported so callers/tests can
 * predict the exact effective key set without re-deriving this filter.
 */
export function intersectWithRotationSet(
  acceptedKeys: ReadonlyArray<ChariotCatalogPublicKey>,
): ChariotCatalogPublicKey[] {
  return acceptedKeys.filter((k) =>
    CHARIOT_CATALOG_PUBLIC_KEYS.some((pinned) => pinned.pem === k.pem),
  );
}

/** Outcome of inspecting an artifact's bytes for the FPS §7.2.6 compact
 *  signing-payload envelope. `legacy` covers every case where the artifact
 *  is not the version-1 compact format — including a JSON parse failure,
 *  a non-object root, a missing/malformed `manifest`, or a plainly absent
 *  `manifest.signingPayloadVersion` — so those degrade to the EXISTING
 *  full-bytes verify path unchanged, exactly as FPS §7.2.6 specifies ("If
 *  absent → the existing full-bytes path, unchanged"). Every other
 *  variant is a distinct fail-closed reason; `compact-ready` carries the
 *  exact bytes the Ed25519 signature is checked against. */
export type CompactSigningPayloadOutcome =
  | { kind: 'legacy' }
  | { kind: 'invalid-version'; detail: string }
  | { kind: 'malformed'; detail: string }
  | { kind: 'empty-leaf-set' }
  | { kind: 'oversize'; detail: string }
  | { kind: 'merkle-mismatch'; detail: string }
  | { kind: 'compact-ready'; payloadBytes: Buffer };

const HEX_SHA256_DIGEST = /^[0-9a-f]{64}$/;

/**
 * FPS §7.2.6 — inspect `artifactBytes` (the already-read, not-yet-trusted
 * `chariot-adapter-bundle.json` bytes) and decide the verify path.
 *
 * Mirrors the producer's own field-validation order
 * (`materializer/signing-payload.ts` `buildCompactSigningPayloadFromBundleJson`
 * + `buildCompactSigningPayload`) so a malformed field is caught with the
 * same specificity on both sides, then recomputes the FPS §7.2.2 Merkle
 * root over `catalog[] ∪ registry[]` (`merkle.ts`, ported verbatim from
 * `materializer/merkle.ts`) and compares it against the claimed
 * `manifest.merkleRoot` BEFORE ever building or size-checking the compact
 * payload — a forged `merkleRoot` that does not match the shipped records
 * is caught here, never handed to a signature attempt.
 *
 * `manifestHash = sha256(canonicalize(manifest))` per FPS §7.2.3, verbatim
 * — `manifest` is the shipped bundle's `manifest` object exactly as
 * serialized (every field the producer writes there, e.g.
 * `{ merkleRoot, signingPayloadVersion, tamperAllowlistVersion }` — this
 * function hashes the FULL parsed manifest object, not a subset, so any
 * field of it changing changes `manifestHash` and therefore the signed
 * payload, exactly as the clause states.
 *
 * MIGRATION NOTE: bundles materialized before the paired producer change
 * lands stamp `manifest.signingPayloadVersion = 1` unconditionally, but
 * their primary `.sig` still covers full bundle bytes (the compact
 * payload exists only as an additive, not-yet-verified sidecar file on
 * that producer). Such a bundle correctly FAILS CLOSED under this branch
 * — this is by design, not a defect: FPS §7.2.6 requires the paired
 * consumer verifier and the producer's primary-signature flip to land "in
 * the same migration window", and the operator re-materializes the live
 * catalog against the updated producer before cutting a release that
 * ships this consumer change. A bundle rejected here because it predates
 * that producer flip needs re-materialization, not a code change.
 */

/**
 * FPS §7.2.3, verbatim: "manifestHash = sha256(canonicalize(manifest))".
 * `manifest` is the FULL shipped bundle manifest object exactly as parsed
 * (every field it carries — merkleRoot, signingPayloadVersion,
 * tamperAllowlistVersion, and any future field) — canonicalize() sorts
 * keys, so this is stable regardless of on-disk key order. Mirrors the
 * producer's own `computeManifestHash` (`materializer/signing-payload.ts`)
 * as its own named, independently-testable function — same pattern as
 * `checkCompactPayloadByteCap` below — so a fixture manifest's hash can be
 * pinned directly without needing a bundle whose catalog[]/registry[]
 * leaves actually hash to that manifest's claimed merkleRoot.
 */
export function computeManifestHash(manifest: Record<string, unknown>): string {
  return createHash('sha256').update(canonicalize(manifest), 'utf-8').digest('hex');
}

export function resolveCompactSigningPayload(artifactBytes: Buffer): CompactSigningPayloadOutcome {
  let parsed: unknown;
  try {
    parsed = JSON.parse(artifactBytes.toString('utf-8'));
  } catch {
    return { kind: 'legacy' };
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { kind: 'legacy' };
  }
  const bundle = parsed as Record<string, unknown>;
  const manifest = bundle['manifest'];
  if (manifest === null || typeof manifest !== 'object' || Array.isArray(manifest)) {
    return { kind: 'legacy' };
  }
  const manifestObj = manifest as Record<string, unknown>;
  const version = manifestObj['signingPayloadVersion'];
  // JSON.parse never yields `undefined` for a PRESENT key — only an absent
  // key reads as `undefined` here, so this correctly distinguishes "field
  // absent" (→ legacy) from "field present as null/0/other" (→ invalid,
  // below), per FPS §7.2.6's "old full-bytes vs new compact-payload" gate.
  if (version === undefined) {
    return { kind: 'legacy' };
  }
  if (version !== 1) {
    return {
      kind: 'invalid-version',
      detail: `manifest.signingPayloadVersion=${JSON.stringify(version)} is not the supported value 1 (FPS §7.2.6)`,
    };
  }

  const merkleRootClaimed = manifestObj['merkleRoot'];
  if (typeof merkleRootClaimed !== 'string' || !HEX_SHA256_DIGEST.test(merkleRootClaimed)) {
    return {
      kind: 'malformed',
      detail: 'manifest.merkleRoot is missing or not a 64-char lowercase-hex SHA-256 digest (FPS §7.2.2)',
    };
  }
  const epoch = bundle['epoch'];
  const catalogVersion = bundle['catalogVersion'];
  if (!Number.isInteger(epoch)) {
    return { kind: 'malformed', detail: 'bundle.epoch is missing or not an integer (FPS §7.2.3)' };
  }
  if (!Number.isInteger(catalogVersion)) {
    return { kind: 'malformed', detail: 'bundle.catalogVersion is missing or not an integer (FPS §7.2.3)' };
  }

  // FPS §7.2.2 leaf set = catalog[] ∪ registry[]; registry[] MAY be empty
  // (CHARIOT-SPEC.md §5.6 envelope table: "registry ... may be empty") but
  // an absent/non-array field on EITHER side is malformed, not "empty" —
  // §5.6 requires `catalog: AdapterEntry[]` (non-empty) and
  // `registry: RegistryEntry[]` (may be empty) to both be present arrays.
  const leaves: MerkleLeafInput[] = [];
  for (const arrayName of ['catalog', 'registry'] as const) {
    const entries = bundle[arrayName];
    if (!Array.isArray(entries)) {
      return { kind: 'malformed', detail: `bundle.${arrayName} is missing or not an array (CHARIOT-SPEC.md §5.6)` };
    }
    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i] as Record<string, unknown> | null;
      const id = entry?.['id'];
      const metadata = entry?.['metadata'] as Record<string, unknown> | undefined;
      const publishHash = metadata?.['publishHash'];
      if (typeof id !== 'string' || id.length === 0) {
        return { kind: 'malformed', detail: `${arrayName}[${i}] has a missing/non-string/empty id (FPS §7.2.1)` };
      }
      if (typeof publishHash !== 'string' || publishHash.length === 0) {
        return {
          kind: 'malformed',
          detail: `${arrayName}[${i}] (id=${id}) has a missing/non-string/empty metadata.publishHash (FPS §7.2.1)`,
        };
      }
      leaves.push({ array: arrayName, id, publishHash });
    }
  }
  if (leaves.length === 0) {
    return { kind: 'empty-leaf-set' };
  }

  const recomputedRoot = computeMerkleRoot(leaves);
  if (recomputedRoot !== merkleRootClaimed) {
    return {
      kind: 'merkle-mismatch',
      detail: `recomputed merkleRoot ${recomputedRoot} != manifest.merkleRoot ${merkleRootClaimed}`,
    };
  }

  const manifestHash = computeManifestHash(manifestObj);

  // FPS §7.2.3 field order is documentation only — canonicalize() sorts
  // object keys lexicographically regardless.
  const serialized = canonicalize({
    manifestHash,
    merkleRoot: merkleRootClaimed,
    epoch,
    catalogVersion,
  });
  const capCheck = checkCompactPayloadByteCap(serialized);
  if (!capCheck.ok) {
    return { kind: 'oversize', detail: capCheck.detail };
  }
  return { kind: 'compact-ready', payloadBytes: Buffer.from(serialized, 'utf-8') };
}

/**
 * FPS §7.2.3, verbatim: "The serialized payload MUST be `< 4096` bytes
 * (asserted at sign time)." Strict `<`; a payload of exactly
 * `MAX_COMPACT_SIGNING_PAYLOAD_BYTES` (4096) or more is rejected. Matches
 * the producer's own `MAX_COMPACT_SIGNING_PAYLOAD_BYTES` assert in
 * `materializer/signing-payload.ts` (`buildCompactSigningPayload`'s
 * `byteLength >= MAX_COMPACT_SIGNING_PAYLOAD_BYTES` throw).
 *
 * Extracted as its own pure, exported function (rather than an inline
 * check in `resolveCompactSigningPayload`) so the cap itself is directly
 * testable: through the public bundle surface this branch is
 * structurally unreachable — `manifestHash`/`merkleRoot` are always
 * exactly 64 hex chars and `epoch`/`catalogVersion` are JS integers whose
 * JSON form never exceeds a few dozen characters, so a real FPS §7.2.3
 * payload is bounded under ~250 bytes by construction (CH-52: "which is
 * ≤4096B by construction ... so there is NO size-based fallback"). This
 * function lets a test drive the cap directly with a synthetic string,
 * independent of whatever bundle shape can realistically produce.
 */
export function checkCompactPayloadByteCap(
  serialized: string,
): { ok: true } | { ok: false; reason: 'compact-payload-oversize'; detail: string } {
  const byteLength = Buffer.byteLength(serialized, 'utf-8');
  if (byteLength >= MAX_COMPACT_SIGNING_PAYLOAD_BYTES) {
    return {
      ok: false,
      reason: 'compact-payload-oversize',
      detail: `${byteLength}/${MAX_COMPACT_SIGNING_PAYLOAD_BYTES}`,
    };
  }
  return { ok: true };
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

  // FPS §7.2.6 consumer lockstep — single version-selected branch, this ONE
  // Chariot artifact (not a per-backend/per-cloud fork). Only
  // chariot-adapter-bundle.json carries the compact-payload envelope
  // (manifest.merkleRoot/signingPayloadVersion, FPS §7.2.2/§7.2.3);
  // chariot-adapter-catalog.json and chariot-mcp-registry.json are outside
  // the Merkle leaf set (FPS §7.2.3: "the compact payload for the bundle
  // only") and always verify full-bytes, unchanged. Runs BEFORE the
  // rotation-set trust decision below so a malformed/unrecognized envelope
  // fails closed on its own merits, independent of which keys the caller
  // supplied.
  let bytesToVerify: Buffer = artifact.bytes;
  if (artifactPath.endsWith('chariot-adapter-bundle.json')) {
    const compact = resolveCompactSigningPayload(artifact.bytes);
    switch (compact.kind) {
      case 'legacy':
        break; // bytesToVerify stays artifact.bytes — existing full-bytes path, unchanged.
      case 'invalid-version':
        return { ok: false, reason: 'signing-payload-version-invalid', detail: compact.detail };
      case 'malformed':
        return { ok: false, reason: 'compact-payload-malformed', detail: compact.detail };
      case 'empty-leaf-set':
        return {
          ok: false,
          reason: 'compact-payload-empty-leaf-set',
          detail: 'catalog[] and registry[] together produced zero Merkle leaves (FPS §7.2.2)',
        };
      case 'oversize':
        return { ok: false, reason: 'compact-payload-oversize', detail: compact.detail };
      case 'merkle-mismatch':
        return { ok: false, reason: 'compact-payload-merkle-root-mismatch', detail: compact.detail };
      case 'compact-ready':
        bytesToVerify = compact.payloadBytes;
        break;
    }
  }

  // CHARIOT-SPEC.md:525 trust anchor (module docstring above). Filtered
  // HERE — after every artifact/.sig existence/size/regular-file check
  // above (those reason codes are about the FILES on disk and are
  // independent of which keys the caller supplied; they must stay
  // reachable with any `acceptedKeys` value, including one with no
  // rotation-set member) and BEFORE the very first `cryptoVerify` call
  // (a key outside the compiled-in rotation set must never be tried).
  // A caller-supplied set that intersects to zero pinned keys is a
  // configuration error distinct from "tried and did not match" — it
  // gets its own reason so operators and tests can tell them apart.
  const trustedKeys = intersectWithRotationSet(acceptedKeys);
  if (trustedKeys.length === 0) {
    return {
      ok: false,
      reason: 'accepted-keys-outside-rotation-set',
      detail:
        `caller-supplied acceptedKeys (${acceptedKeys.length}) contained none in the ` +
        'compiled-in CHARIOT_CATALOG_PUBLIC_KEYS rotation set (CHARIOT-SPEC.md:525 trust anchor)',
    };
  }
  // Iterates `trustedKeys`, NEVER the raw `acceptedKeys` — a key outside
  // the compiled-in rotation set was already dropped above and is not
  // tried here (CHARIOT-SPEC.md:525 trust anchor).
  for (const key of trustedKeys) {
    try {
      // Look up the cached KeyObject for this PEM. Node's crypto otherwise
      // re-parses the PEM string into an ASN.1 KeyObject on every call.
      // With ≥3 signed artifacts loaded per boot × N keys, that's 3·N
      // PEM parses per boot — pure repeated work since the key set is
      // module-frozen. Cache miss falls back to parsing on the fly so
      // callers passing custom keys (test fixtures, eval suite) still
      // work without pre-registering.
      const keyObject = getKeyObject(key.pem);
      // `bytesToVerify` is the compact FPS §7.2.3 payload when the version
      // gate above selected it, otherwise the full artifact bytes
      // (unchanged legacy behavior). The RETURNED `bytes` is always the
      // full artifact — downstream callers (ChariotState.ts etc.) parse the
      // whole bundle JSON regardless of which bytes the signature covered.
      if (cryptoVerify(null, bytesToVerify, keyObject, sigBytes)) {
        return { ok: true, bytes: artifact.bytes, keyId: key.id };
      }
    } catch {
      /* try the next key */
    }
  }
  return {
    ok: false,
    reason: 'signature-verification-failed',
    detail: `tried ${trustedKeys.length} key(s)`,
  };
}

/**
 * Verify-or-null convenience used by every fast-path catalog loader.
 * Returns verified bytes or null. Logs every failure mode EXCEPT
 * `artifact-not-found` — that one is the legitimate "no catalog
 * installed yet" state for a fresh install before the publisher has
 * run, and would generate alert noise on every wizard launch.
 *
 * CHARIOT-SPEC.md:525 trust anchor (module docstring above): forwards
 * `acceptedKeys` unfiltered into `verifyAndReadArtifact`, which is the sole
 * choke point that intersects it against the compiled-in rotation set —
 * this function adds no separate key logic and cannot be used to bypass
 * that gate.
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

/**
 * Fail-closed variant for callers that must distinguish an ABSENT artifact
 * (legitimate "not installed yet") from a PRESENT-BUT-INVALID one (tamper,
 * bad signature, stale epoch). §4.2/§5.6.
 *
 *  - Absent (artifact-not-found) → returns null; caller may fall back to
 *    BM25-only or any degraded path appropriate for a fresh install.
 *  - Present but invalid (any other VerifyReason) → throws an Error so
 *    the caller fails closed and routing never begins against a tampered
 *    or stale bundle.
 *
 * All failure modes are logged before throwing/returning so operators
 * always see the reason in structured logs.
 *
 * CHARIOT-SPEC.md:525 trust anchor (module docstring above): like
 * `verifiedReadOrNull`, forwards `acceptedKeys` unfiltered into
 * `verifyAndReadArtifact` — the sole choke point that enforces the
 * rotation-set intersection. A caller-supplied set with no member in
 * `CHARIOT_CATALOG_PUBLIC_KEYS` is therefore fail-closed here too (throws,
 * exactly like any other present-but-invalid artifact).
 */
export function verifiedReadFailClosed(
  artifactPath: string,
  log: LoggerInterface,
  label: string,
  acceptedKeys: ReadonlyArray<ChariotCatalogPublicKey> = CHARIOT_CATALOG_PUBLIC_KEYS,
  maxBytes: number = MAX_CATALOG_BYTES,
): Buffer | null {
  const r = verifyAndReadArtifact(artifactPath, acceptedKeys, maxBytes);
  if (r.ok) return r.bytes;
  if (r.reason === 'artifact-not-found') return null; // legitimately absent
  log.error('catalog signature gate failed — fail-closed', {
    label,
    reason: r.reason,
    path: artifactPath,
    detail: r.detail,
  });
  throw new Error(
    `retrieval manifest present but verification failed (${r.reason}): ${r.detail ?? 'no detail'}`,
  );
}
