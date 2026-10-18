/**
 * @epicai/chariot — Hash Chain Length Attestation
 *
 * Periodic, signed assertion of the current hash-chain length and head
 * hash. Closes the truncation weakness documented as Mode 5 in
 * test/ai-evals/07-hash-chain-tamper.mjs: a bare hash chain with no
 * external length anchor cannot detect the silent removal of trailing
 * records — the surviving prefix is internally well-formed and verifies
 * clean. A length attestation, signed with the same Ed25519 key chain
 * that signs licenses and the adapter catalog, lets a verifier compare
 * the current chain length against the most recent signed assertion and
 * flag truncation as soon as `currentLength < lastAttestedLength`.
 *
 * Storage contract (HARD — never violate):
 *   <packageRoot>/audit/length-attestations/<chain-id>-<epoch>.json
 *   - Append-only. Producers MUST write a NEW file per attestation,
 *     keyed by the epoch-millisecond timestamp. NEVER overwrite a prior
 *     attestation. A verifier that finds a newer attestation with a
 *     SHORTER length than an older one MUST treat it as a truncation
 *     alarm (`detectTruncation` below); silently overwriting would
 *     erase the evidence the alarm depends on.
 *   - Mode 0o644 on the file, 0o755 on the directory.
 *
 * Schema (canonicalized for signing — see `canonicalStringify`):
 *   { schemaVersion: 1
 *   , chainId:        string         // operator-assigned chain id
 *   , length:         number         // chain length at attestation time
 *   , headHash:       string         // hex-encoded SHA-256 of the chain head
 *   , attestedAt:     string         // ISO-8601 UTC instant
 *   , signature:      string         // base64url Ed25519 signature
 *   }
 * The `signature` field is excluded from the canonical payload that the
 * signer hashes; `signLengthAttestation` constructs the payload by
 * dropping `signature` before canonicalization, mirroring the pattern
 * used by `loadRevocationList()` in src/license/loader.ts.
 *
 * CLI surface:
 *   `chariot audit attest` — produce a length attestation for the
 *                            current chain and write it to disk.
 *   Wired in src/bin/chariot.ts under the `audit` subcommand.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { sign as edSign, verify as edVerify, type KeyObject } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalStringify } from '../../util/canonical-json.js';
import { atomicWriteNew } from './auditFs.js';
import { resolvePublicKey, resolvePrivateKey } from './key-utils.js';

export interface LengthAttestation {
  schemaVersion: 1;
  chainId: string;
  length: number;
  headHash: string;
  attestedAt: string;
  signature: string;
}

export interface LengthAttestationPayload {
  schemaVersion: 1;
  chainId: string;
  length: number;
  headHash: string;
  attestedAt: string;
}

/**
 * CHARIOT::§9.8.3::3 — verifier-API return shape for verifyLengthAttestation,
 * pinned verbatim to CHARIOT-SPEC.md §9.8.3: "Returns {valid: boolean,
 * attestedAt: Date, chainId: string, attestedLength: number, error?: string}."
 */
export interface AttestationVerifyResult {
  valid: boolean;
  attestedAt: Date;
  chainId: string;
  attestedLength: number;
  error?: string;
}

/**
 * Build the canonical signing payload for a length attestation. Mirrors
 * the loadRevocationList() pattern: signature is computed over the
 * canonical JSON of every field except `signature` itself.
 */
export function canonicalAttestationPayload(p: LengthAttestationPayload): Buffer {
  return Buffer.from(canonicalStringify(p), 'utf-8');
}

/**
 * Sign a length attestation with the operator-held Ed25519 private key.
 * Returns a complete `LengthAttestation` ready to persist.
 *
 * @param payload      The unsigned attestation (no signature field).
 * @param privateKeyPem PEM-encoded Ed25519 private key (PKCS#8 SPKI).
 *                      Must be the private half of a key whose public
 *                      half is in the verifier's accepted list.
 */
export function signLengthAttestation(
  payload: LengthAttestationPayload,
  privateKeyPem: string | Buffer | KeyObject,
): LengthAttestation {
  if (payload.schemaVersion !== 1) {
    throw new TypeError('signLengthAttestation: schemaVersion must be 1');
  }
  if (!Number.isInteger(payload.length) || payload.length < 0) {
    throw new TypeError('signLengthAttestation: length must be a non-negative integer');
  }
  if (!/^[0-9a-f]{64}$/.test(payload.headHash) && payload.length > 0) {
    throw new TypeError('signLengthAttestation: headHash must be 64-hex SHA-256 for non-empty chains');
  }
  const key = resolvePrivateKey(privateKeyPem);
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new TypeError('signLengthAttestation: key must be Ed25519');
  }
  const sig = edSign(null, canonicalAttestationPayload(payload), key);
  return { ...payload, signature: sig.toString('base64url') };
}

/**
 * Verify a length attestation against a public key.
 *
 * CHARIOT::§9.8.3::3 — "The verifier API verifyLengthAttestation(att,
 * publicKeyPem) SHALL return {valid, attestedAt, chainId, attestedLength,
 * error?}." (CHARIOT-SPEC.md §9.8.3, Verifier API surface: "verifyLengthAttestation(att:
 * LengthAttestation, publicKeyPem: string): Promise<AttestationVerifyResult>").
 *
 * Never throws — every decode/parse/verify failure resolves `valid: false`
 * with a populated `error` so callers can await this without a try/catch.
 */
export async function verifyLengthAttestation(
  att: LengthAttestation,
  publicKeyPem: string,
): Promise<AttestationVerifyResult> {
  const chainId = att?.chainId as string;
  const attestedLength = (att && Number.isInteger(att.length) ? att.length : NaN) as number;
  const attestedAt = new Date(att?.attestedAt ?? NaN);
  try {
    if (!att || att.schemaVersion !== 1) {
      return { valid: false, attestedAt, chainId, attestedLength, error: 'schemaVersion must be 1' };
    }
    if (typeof att.signature !== 'string' || att.signature.length === 0) {
      return { valid: false, attestedAt, chainId, attestedLength, error: 'missing or empty signature' };
    }
    if (!Number.isInteger(att.length) || att.length < 0) {
      return { valid: false, attestedAt, chainId, attestedLength, error: 'length must be a non-negative integer' };
    }
    const key = resolvePublicKey(publicKeyPem);
    if (key.asymmetricKeyType !== 'ed25519') {
      return { valid: false, attestedAt, chainId, attestedLength, error: 'key must be Ed25519' };
    }
    const payload: LengthAttestationPayload = {
      schemaVersion: att.schemaVersion,
      chainId: att.chainId,
      length: att.length,
      headHash: att.headHash,
      attestedAt: att.attestedAt,
    };
    const sigBuf = Buffer.from(att.signature, 'base64url');
    const ok = edVerify(null, canonicalAttestationPayload(payload), key, sigBuf);
    return ok
      ? { valid: true, attestedAt, chainId, attestedLength }
      : { valid: false, attestedAt, chainId, attestedLength, error: 'signature verification failed' };
  } catch (e) {
    return { valid: false, attestedAt, chainId, attestedLength, error: e instanceof Error ? e.message : String(e) };
  }
}

/**
 * Truncation detector. Compares the current chain length against the
 * highest length ever recorded in any prior attestation for the same
 * chainId. If the current length is strictly less than the
 * last-attested length, the chain has been silently truncated —
 * the operator (or attacker) removed records the attestation already
 * promised existed.
 *
 * Returns `{ truncated, lastAttestedLength }`. `lastAttestedLength` is
 * the MAX over the attestation set (not the chronologically newest)
 * because an attacker who can write into the attestation directory
 * could otherwise issue a fresh-but-shorter attestation to mask the
 * truncation. Taking the max preserves the alarm in that case.
 */
export function detectTruncation(
  currentLength: number,
  attestations: ReadonlyArray<LengthAttestation>,
): { truncated: boolean; lastAttestedLength: number } {
  let lastAttestedLength = 0;
  for (const a of attestations) {
    if (Number.isInteger(a.length) && a.length > lastAttestedLength) {
      lastAttestedLength = a.length;
    }
  }
  return { truncated: currentLength < lastAttestedLength, lastAttestedLength };
}

/**
 * CHARIOT::§9.8.3::4 — "On each audit export or periodic health check the
 * verifier SHALL reconcile the current chain length against the most recent
 * attested length, and IF currentLength < attestedLength THEN emit CRITICAL
 * audit.tail_truncation_detected{chainId,attestedLength,currentLength} and
 * halt export." (CHARIOT-SPEC.md §9.8.3)
 *
 * Single reusable reconciliation entry point so `chariot audit verify-length`
 * and any export/health-check caller (e.g. the `/audit-logs` admin route)
 * share one implementation and cannot drift. Loads attestations for
 * `chainId` from `<packageRoot>/audit/length-attestations/`, keeps only
 * those that verify against `publicKeyPem`, and reconciles the max verified
 * attested length against `currentLength` via {@link detectTruncation}.
 *
 * Fail-closed semantics (CHARIOT §9.8.3, 2026-09-01): when no
 * attestation exists for `chainId` there is nothing to reconcile against and
 * the result is `truncated: false, attestedLength: 0, unverifiable: false`
 * (the chain was never attested). When attestations DO exist but NONE can be
 * verified — because no verification key was supplied or every signature
 * fails — the result is `unverifiable: true`: the caller MUST treat the
 * export as unverifiable and halt, never proceed as if nothing was attested.
 * A forged or mis-signed attestation is excluded from the reconciled set, so
 * it can never mask real truncation; but an attested chain that cannot be
 * checked is never silently served.
 */
/**
 * CHARIOT::§9.8.1::3 — "Historical records remain verifiable only if the
 * old public key is retained in a multi-key verification set (CH-03
 * pattern)." `LengthAttestation` carries no `kid` field (unlike a
 * kid-tagged chain record), so there is no signer identity to route by —
 * multi-key verification here means trying every retained key and
 * accepting the attestation if it validates under ANY of them, which
 * gives the identical practical outcome (a record signed under a
 * RETIRED-but-still-retained key still verifies) without a schema change
 * to the on-disk attestation format.
 */
export type VerifyKeys = string | ReadonlyMap<string, KeyObject>;

function verifyKeyPemCandidates(verifyKeys: VerifyKeys | undefined): string[] {
  if (!verifyKeys) return [];
  if (typeof verifyKeys === 'string') return [verifyKeys];
  return Array.from(verifyKeys.values(), (k) => k.export({ type: 'spki', format: 'pem' }) as string);
}

export async function reconcileChainLength(
  packageRoot: string,
  chainId: string,
  currentLength: number,
  verifyKeys?: VerifyKeys,
): Promise<{ truncated: boolean; attestedLength: number; currentLength: number; unverifiable: boolean }> {
  const attestations = loadAttestations(packageRoot, chainId);
  // verifyLengthAttestation is now Promise-returning per CHARIOT::§9.8.3::3
  // (verifier API surface); reconcile sequentially so a caller awaiting this
  // function observes every attestation checked before it resolves.
  const candidates = verifyKeyPemCandidates(verifyKeys);
  const verified: LengthAttestation[] = [];
  for (const a of attestations) {
    for (const pem of candidates) {
      const r = await verifyLengthAttestation(a, pem);
      if (r.valid) {
        verified.push(a);
        break; // valid under this key — no need to try the rest for this attestation
      }
    }
  }
  // CHARIOT::§9.8.3::4 — attested but unverifiable is a fail-closed condition.
  const unverifiable = attestations.length > 0 && verified.length === 0;
  const { truncated, lastAttestedLength } = detectTruncation(currentLength, verified);
  return { truncated, attestedLength: lastAttestedLength, currentLength, unverifiable };
}

/**
 * Persist an attestation to the on-disk append-only directory.
 * Filename: `<chainId>-<epoch>.json` where `epoch` is the millisecond
 * timestamp parsed from `attestedAt`. NEVER overwrite an existing
 * file — if collision occurs (two attestations for the same chain at
 * the same millisecond), suffix with `.dup-<n>.json` so the original
 * evidence remains untouched.
 */
export function persistAttestation(
  packageRoot: string,
  att: LengthAttestation,
): string {
  const dir = join(packageRoot, 'audit', 'length-attestations');
  const epoch = Date.parse(att.attestedAt);
  if (!Number.isFinite(epoch)) {
    throw new TypeError('persistAttestation: attestedAt is not a parseable ISO-8601 instant');
  }
  let filename = `${att.chainId}-${epoch}.json`;
  // Append-only collision handling
  let dup = 0;
  while (true) {
    try {
      // atomicWriteNew uses 'wx' flag (fail-if-exists): the security-relevant
      // invariant lives in one place — auditFs.ts.
      return atomicWriteNew(dir, filename, JSON.stringify(att, null, 2));
    } catch (e) {
      const err = e as NodeJS.ErrnoException;
      if (err.code !== 'EEXIST') throw err;
      dup += 1;
      filename = `${att.chainId}-${epoch}.dup-${dup}.json`;
      if (dup > 1024) throw new Error('persistAttestation: too many collisions');
    }
  }
}

/**
 * Load all attestations for a given chainId from the on-disk
 * append-only directory. Returns an empty array if the directory does
 * not exist. Skips files that fail to parse — they cannot contribute
 * evidence either way and the directory may legitimately contain
 * sibling artifacts in future schema versions.
 */
export function loadAttestations(
  packageRoot: string,
  chainId: string,
): LengthAttestation[] {
  const dir = join(packageRoot, 'audit', 'length-attestations');
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return [];
  }
  const out: LengthAttestation[] = [];
  for (const name of entries) {
    if (!name.startsWith(`${chainId}-`) || !name.endsWith('.json')) continue;
    try {
      const raw = readFileSync(join(dir, name), 'utf-8');
      const parsed = JSON.parse(raw) as LengthAttestation;
      if (parsed && parsed.schemaVersion === 1 && parsed.chainId === chainId) {
        out.push(parsed);
      }
    } catch {
      // skip unparseable
    }
  }
  return out;
}
