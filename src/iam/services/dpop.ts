/**
 * IAM — RFC 9449 DPoP proof verification.
 *
 * DPoP (Demonstrating Proof-of-Possession) binds an access token to a
 * client-held key pair. The client sends a fresh DPoP proof JWT in the
 * `DPoP` header on every request the token authorizes. This module
 * verifies the proof per RFC 9449 §4.3:
 *
 *   - typ MUST be "dpop+jwt"
 *   - alg MUST be an asymmetric signing algorithm (excludes "none", HS*)
 *   - jwk MUST be present in the header (the proof's signing key)
 *   - signature MUST verify using that jwk
 *   - htm MUST equal the request method
 *   - htu MUST equal the request URI (scheme + host + port + path,
 *     after stripping query string and fragment per §4.3)
 *   - iat MUST be within ±60 seconds of now (default; tunable)
 *   - jti MUST be present and MUST NOT have been seen for this jwk
 *     within the iat tolerance window (replay protection per §11.1).
 *   - ath, when required (resource calls), MUST equal
 *     base64url(SHA-256(access_token)).
 *
 * Two functions exported:
 *   - verifyDpopProofForTokenEndpoint: used at /oauth/token + /oauth/revoke
 *     where there is no inbound access token yet, so `ath` is not required.
 *     Returns the JWK SHA-256 thumbprint (the value the issuer stamps as
 *     cnf.jkt on the issued token).
 *   - verifyDpopProofForResource: used by middleware on every protected
 *     tool call. Asserts `ath` matches the bound token AND the proof's
 *     jkt matches the token's cnf.jkt.
 */

import { calculateJwkThumbprint, importJWK, jwtVerify } from 'jose';
import type { JWK, JWTHeaderParameters } from 'jose';
import { createHash } from 'node:crypto';

import type { JtiCachePort } from './id-jag-validator.js';

const SUPPORTED_ALGS = new Set(['RS256', 'ES256', 'EdDSA', 'PS256']);
const IAT_TOLERANCE_SECONDS = 60; // RFC 9449 §4.3 recommends ≤60s
const JTI_REPLAY_TTL_SECONDS = 90; // covers ±60s iat skew + slack
const DPOP_JWT_TYP = 'dpop+jwt';

export type DpopErrorCode =
  | 'invalid_dpop_proof'
  | 'use_dpop_nonce'; // reserved; not emitted today

export interface DpopError {
  ok: false;
  code: DpopErrorCode;
  reason: string;
}

export interface DpopVerifySuccess {
  ok: true;
  /** SHA-256 JWK thumbprint (base64url) — the cnf.jkt value. */
  jkt: string;
  jti: string;
}

export interface DpopProofInput {
  /** Raw value of the `DPoP` request header (a JWT). */
  proof: string;
  /** Request HTTP method, normalised to uppercase. */
  htm: string;
  /**
   * Request URI without query or fragment, exactly as the proof's `htu`
   * claim should appear. The caller is responsible for the
   * scheme+host+port+path canonicalisation per RFC 9449 §4.3.
   */
  htu: string;
  jtiCache: JtiCachePort;
  /** Override the wall clock; tests use this. Default Date.now(). */
  nowMs?: number;
  iatToleranceSeconds?: number;
}

export interface DpopResourceProofInput extends DpopProofInput {
  /** The bound access token; ath check derives base64url(SHA-256(token)). */
  accessToken: string;
  /** The cnf.jkt claim from the access token. */
  expectedJkt: string;
}

// ── Verifier (shared core) ──────────────────────────────────────────────────

async function verifyCore(input: DpopProofInput): Promise<DpopVerifySuccess | DpopError> {
  const nowMs = input.nowMs ?? Date.now();
  const nowSec = Math.floor(nowMs / 1000);
  const tol = input.iatToleranceSeconds ?? IAT_TOLERANCE_SECONDS;

  let parts: string[];
  try {
    parts = input.proof.split('.');
    if (parts.length !== 3) throw new Error('not 3 segments');
  } catch (e) {
    return errDpop(`malformed DPoP proof: ${(e as Error).message}`);
  }

  let header: JWTHeaderParameters & { jwk?: JWK; typ?: string };
  try {
    const headerJson = Buffer.from(parts[0], 'base64url').toString('utf-8');
    header = JSON.parse(headerJson) as JWTHeaderParameters & { jwk?: JWK; typ?: string };
  } catch {
    return errDpop('DPoP proof header is not valid base64url JSON');
  }

  if (header.typ !== DPOP_JWT_TYP) {
    return errDpop(`DPoP proof typ must be "${DPOP_JWT_TYP}", got "${String(header.typ)}"`);
  }
  const alg = typeof header.alg === 'string' ? header.alg : '';
  if (!SUPPORTED_ALGS.has(alg)) {
    return errDpop(`DPoP proof alg "${alg}" is not supported`);
  }
  if (!header.jwk || typeof header.jwk !== 'object') {
    return errDpop('DPoP proof header missing required jwk');
  }
  // RFC 9449 §4.2: the jwk MUST be a public key (no `d` private parameter).
  if ('d' in header.jwk) {
    return errDpop('DPoP proof jwk MUST be a public key (private key parameter "d" present)');
  }

  let key: CryptoKey | Uint8Array;
  try {
    key = await importJWK(header.jwk, alg);
  } catch (e) {
    return errDpop(`DPoP proof jwk import failed: ${(e as Error).message}`);
  }

  let verified;
  try {
    verified = await jwtVerify(input.proof, key, {
      algorithms: [alg],
      typ: DPOP_JWT_TYP,
      currentDate: new Date(nowMs),
    });
  } catch (e) {
    return errDpop(`DPoP proof signature/claim validation failed: ${(e as Error).message}`);
  }

  const payload = verified.payload as { htm?: unknown; htu?: unknown; iat?: unknown; jti?: unknown; ath?: unknown };

  if (typeof payload.htm !== 'string' || payload.htm !== input.htm) {
    return errDpop(`DPoP proof htm "${String(payload.htm)}" does not match request method "${input.htm}"`);
  }
  if (typeof payload.htu !== 'string' || normaliseHtu(payload.htu) !== normaliseHtu(input.htu)) {
    return errDpop(`DPoP proof htu "${String(payload.htu)}" does not match request URI "${input.htu}"`);
  }
  const iat = typeof payload.iat === 'number' ? payload.iat : NaN;
  if (!Number.isFinite(iat) || iat > nowSec + tol || iat < nowSec - tol) {
    return errDpop(`DPoP proof iat outside ±${tol}s tolerance`);
  }
  if (typeof payload.jti !== 'string' || payload.jti.length === 0) {
    return errDpop('DPoP proof missing required jti claim');
  }

  // JWK thumbprint (cnf.jkt). RFC 7638 SHA-256 base64url.
  const jkt = await calculateJwkThumbprint(header.jwk, 'sha256');

  // Replay protection scoped by jkt so different clients can reuse jti uuids.
  const reserved = await input.jtiCache.reserve(`dpop:${jkt}`, payload.jti, JTI_REPLAY_TTL_SECONDS);
  if (!reserved) {
    return errDpop(`DPoP proof jti "${payload.jti}" replay detected`);
  }

  // ath check (resource endpoints only; caller wraps).
  if ('ath' in payload && typeof payload.ath !== 'string') {
    return errDpop('DPoP proof ath, when present, must be a string');
  }

  return { ok: true, jkt, jti: payload.jti };
}

// ── Token-endpoint verifier (issuance side) ──────────────────────────────────

export async function verifyDpopProofForTokenEndpoint(
  input: DpopProofInput,
): Promise<DpopVerifySuccess | DpopError> {
  return verifyCore(input);
}

// ── Resource verifier (middleware side) ──────────────────────────────────────

export async function verifyDpopProofForResource(
  input: DpopResourceProofInput,
): Promise<DpopVerifySuccess | DpopError> {
  const core = await verifyCore(input);
  if (!core.ok) return core;
  if (core.jkt !== input.expectedJkt) {
    return errDpop(`DPoP proof jkt does not match access token cnf.jkt`);
  }
  // Re-decode the payload to read ath (verifyCore already verified signature).
  const parts = input.proof.split('.');
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf-8')) as { ath?: unknown };
  const expectedAth = base64UrlSha256(input.accessToken);
  if (payload.ath !== expectedAth) {
    return errDpop(`DPoP proof ath "${String(payload.ath)}" does not match SHA-256 of access token`);
  }
  return core;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function errDpop(reason: string): DpopError {
  return { ok: false, code: 'invalid_dpop_proof', reason };
}

function base64UrlSha256(input: string): string {
  return createHash('sha256').update(input).digest('base64url');
}

/**
 * RFC 9449 §4.3 htu normalisation — strip query string and fragment from
 * a URL. Both sides of the htu comparison go through this; mismatch on
 * scheme, host, port, or path rejects.
 */
export function normaliseHtu(url: string): string {
  // RFC 9449 §4.3: strip query + fragment only. Preserve trailing slash
  // and path case so that `/foo` and `/foo/` compare distinctly — they
  // are different URIs to most resource servers and conflating them
  // weakens the DPoP proof binding.
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}${u.pathname}`;
  } catch {
    return url;
  }
}
