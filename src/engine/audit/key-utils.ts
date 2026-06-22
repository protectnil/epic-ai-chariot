/**
 * @epicai/chariot — Audit Key Resolution Helpers
 *
 * Single location for the duck-type KeyObject-vs-PEM resolver that
 * previously appeared in anchor.ts, length-attestation.ts, and
 * src/license/binding.ts. Centralising here means the detection
 * heuristic (`'asymmetricKeyType' in k`) is tested and changed in one
 * place only.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { createPublicKey, createPrivateKey, type KeyObject } from 'node:crypto';

/**
 * Resolve a public key supplied as a KeyObject, PEM string, or DER Buffer
 * into a `KeyObject`. If `k` is already a `KeyObject` it is returned
 * unchanged — no copy is made.
 */
export function resolvePublicKey(k: KeyObject | string | Buffer): KeyObject {
  if (k instanceof Object && 'asymmetricKeyType' in (k as object)) {
    return k as KeyObject;
  }
  return createPublicKey(k as string | Buffer);
}

/**
 * Resolve a private key supplied as a KeyObject, PEM string, or DER Buffer
 * into a `KeyObject`. If `k` is already a `KeyObject` it is returned
 * unchanged — no copy is made.
 */
export function resolvePrivateKey(k: KeyObject | string | Buffer): KeyObject {
  if (k instanceof Object && 'asymmetricKeyType' in (k as object)) {
    return k as KeyObject;
  }
  return createPrivateKey(k as string | Buffer);
}
