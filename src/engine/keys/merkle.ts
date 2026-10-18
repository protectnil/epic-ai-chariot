/**
 * @epicai/chariot — Bundle-wide Merkle root, RFC 6962, normative per FPS §7.2.2.
 *
 * Verbatim port of the upstream materializer's
 * `materializer/merkle.ts` (`computeMerkleRoot` + its helpers), so the
 * Chariot-side recomputation in `verifyCatalogSignature.ts` derives a
 * byte-identical root from the same leaf inputs as the producer — any
 * divergence here would make every legitimate bundle fail the new
 * compact-payload verify path (FPS §7.2.6).
 *
 * Governing clause (FPS §7.2.2, exact bytes,
 * FABRIQUE-PRODUCT-SPEC-MAY-2026.md:701-704):
 *   "The materializer MUST write `manifest.merkleRoot` computed over the
 *   namespaced union of both shipped arrays:
 *   - Leaf set = `catalog[] ∪ registry[]`; each leaf keyed `(array, id)`,
 *     `array ∈ {"catalog","registry"}`.
 *   - Leaf bytes `d = canonicalize({ array, id, publishHash })` via the
 *     shared `canonicalize()` (`shared/audit-chain.ts:51`); sort ascending
 *     by tuple `(array, id)` byte-wise on UTF-8 — total order even when an
 *     `id` appears in both arrays.
 *   - `H = SHA-256`. Leaf `MTH({d}) = H(0x00 ‖ d)`. Interior (n>1): `k` =
 *     largest power of two `< n`; `MTH(D) = H(0x01 ‖ MTH(D[0:k]) ‖
 *     MTH(D[k:n]))`. No last-node duplication (CVE-2012-2459-safe). Empty
 *     tree = `H("")`; a zero-record bundle is a fail-closed release error.
 *     `merkleRoot` = lowercase-hex of the 32-byte root."
 *
 * CH-51 (CHARIOT-SPEC.md:2165 table) reproduces the same leaf-set
 * definition and states the consumer MUST "recompute each received
 * adapter's `publishHash`, rebuild the merkleRoot, and verify the Ed25519
 * signature ... any byte change to any adapter changes its hash → changes
 * the root → fails the signature, with the offending adapter pinpointed" —
 * this module is the "rebuild the merkleRoot" half of that consumer
 * obligation; `verifyCatalogSignature.ts` supplies the leaves it reads off
 * an already-downloaded, not-yet-trusted bundle.
 *
 * The "zero-record bundle is a fail-closed release error" sentence is a
 * PRODUCER release-gate concern (the same distinction the producer's own
 * module docstring draws) — `computeMerkleRoot(([])) === H("")` per the
 * formula, exactly as the producer's implementation returns; the CONSUMER
 * fail-closed decision for an empty leaf set is made by the caller in
 * `verifyCatalogSignature.ts`, not by this pure function.
 *
 * Pure — no I/O, no imports beyond `node:crypto` and the local
 * `canonicalize` port.
 */

import { createHash } from 'node:crypto';
import { canonicalize } from './canonicalize.js';

/** One (array, id, publishHash) leaf input, pre-sort. */
export interface MerkleLeafInput {
  array: 'catalog' | 'registry';
  id: string;
  publishHash: string;
}

function sha256(...parts: Buffer[]): Buffer {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest();
}

/** Leaf hash: MTH({d}) = H(0x00 ‖ d). */
function leafHash(d: Buffer): Buffer {
  return sha256(Buffer.from([0x00]), d);
}

/** Interior hash: MTH(D) = H(0x01 ‖ MTH(D[0:k]) ‖ MTH(D[k:n])). */
function interiorHash(left: Buffer, right: Buffer): Buffer {
  return sha256(Buffer.from([0x01]), left, right);
}

/** Largest power of two strictly less than n (n > 1). RFC 6962 §2.1. */
function largestPowerOfTwoLessThan(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/**
 * RFC 6962 Merkle Tree Hash over raw leaf-data buffers (each buffer is the
 * canonicalized `d` for one leaf, NOT yet leaf-hashed). No last-node
 * duplication: the split at `k` always yields two non-empty halves for any
 * n > 1, so the classic CVE-2012-2459 duplicate-leaf attack is structurally
 * unreachable.
 */
function merkleTreeHash(data: ReadonlyArray<Buffer>): Buffer {
  const n = data.length;
  if (n === 0) return sha256(Buffer.alloc(0)); // Empty tree = H("").
  if (n === 1) return leafHash(data[0]!);
  const k = largestPowerOfTwoLessThan(n);
  return interiorHash(
    merkleTreeHash(data.slice(0, k)),
    merkleTreeHash(data.slice(k, n)),
  );
}

/**
 * Compute `manifest.merkleRoot`: lowercase-hex SHA-256 Merkle root over the
 * namespaced union of catalog[] and registry[] leaves, keyed (array, id).
 *
 * Sorts ascending by the (array, id) tuple, byte-wise on UTF-8 — a total
 * order even when the same `id` appears in both arrays.
 */
export function computeMerkleRoot(
  leaves: ReadonlyArray<MerkleLeafInput>,
): string {
  const sorted = [...leaves].sort((a, b) => {
    const arrayCmp = Buffer.compare(
      Buffer.from(a.array, 'utf-8'),
      Buffer.from(b.array, 'utf-8'),
    );
    if (arrayCmp !== 0) return arrayCmp;
    return Buffer.compare(
      Buffer.from(a.id, 'utf-8'),
      Buffer.from(b.id, 'utf-8'),
    );
  });
  const data = sorted.map((leaf) =>
    Buffer.from(
      canonicalize({
        array: leaf.array,
        id: leaf.id,
        publishHash: leaf.publishHash,
      }),
      'utf-8',
    ),
  );
  return merkleTreeHash(data).toString('hex');
}
