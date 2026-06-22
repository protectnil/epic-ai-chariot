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
 * Verify a length attestation against a public key. Returns `true` IFF
 * the Ed25519 signature is valid over the canonical payload of the
 * attestation. Never throws — returns `false` on any decode/parse/
 * verify failure so callers can treat verification as a pure boolean.
 */
export function verifyLengthAttestation(
  att: LengthAttestation,
  publicKeyPem: string | Buffer | KeyObject,
): boolean {
  try {
    if (!att || att.schemaVersion !== 1) return false;
    if (typeof att.signature !== 'string' || att.signature.length === 0) return false;
    if (!Number.isInteger(att.length) || att.length < 0) return false;
    const key = resolvePublicKey(publicKeyPem);
    if (key.asymmetricKeyType !== 'ed25519') return false;
    const payload: LengthAttestationPayload = {
      schemaVersion: att.schemaVersion,
      chainId: att.chainId,
      length: att.length,
      headHash: att.headHash,
      attestedAt: att.attestedAt,
    };
    const sigBuf = Buffer.from(att.signature, 'base64url');
    return edVerify(null, canonicalAttestationPayload(payload), key, sigBuf);
  } catch {
    return false;
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
  return {
    truncated: currentLength < lastAttestedLength,
    lastAttestedLength,
  };
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
