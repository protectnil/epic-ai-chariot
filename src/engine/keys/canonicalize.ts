/**
 * @epicai/chariot — Deterministic canonical JSON serializer.
 *
 * Ported from the upstream materializer's shared/audit-chain.ts (lines 34-84)
 * for byte-identical parity: this module's `canonicalize()` is the SAME
 * algorithm the materializer uses to build the FPS §7.2.3 compact signing
 * payload (`signingPayload = canonicalize({ manifestHash, merkleRoot,
 * epoch, catalogVersion })`) and the FPS §7.2.2 Merkle leaf bytes
 * (`d = canonicalize({ array, id, publishHash })`). A Chariot-side
 * recomputation that used a DIFFERENT canonicalizer would produce
 * different bytes for the same logical object and every legitimate
 * signature would fail to verify — so this is a verbatim port, not a
 * reimplementation: same key-sort rule, same Date/bigint/primitive
 * handling, same EXCLUDED_KEYS set, same toJSON-honoring branch, same
 * array-order-preserving branch.
 *
 * FPS §7.2.2 (FABRIQUE-PRODUCT-SPEC-MAY-2026.md:701-704), verbatim:
 *   "Leaf bytes `d = canonicalize({ array, id, publishHash })` via the
 *   shared `canonicalize()` (`shared/audit-chain.ts:51` ...)."
 *
 * FPS §7.2.3 (FABRIQUE-PRODUCT-SPEC-MAY-2026.md:706), verbatim:
 *   "`signingPayload = canonicalize({ manifestHash, merkleRoot, epoch,
 *   catalogVersion })`, where `manifestHash = sha256(canonicalize(manifest))`."
 *
 * Producer source (`shared/audit-chain.ts:34-84`,
 * read verbatim, no paraphrase):
 *
 *   const EXCLUDED_KEYS = new Set<string>(['_id', CHAIN_PREV_HASH_FIELD, CHAIN_HASH_FIELD]);
 *
 *   export function canonicalize(value: unknown): string {
 *     if (value === null || value === undefined) return 'null';
 *     if (value instanceof Date) return JSON.stringify(value.toISOString());
 *     const t = typeof value;
 *     if (t === 'bigint') return JSON.stringify((value as bigint).toString());
 *     if (t === 'string' || t === 'number' || t === 'boolean') return JSON.stringify(value);
 *     if (Array.isArray(value)) {
 *       return '[' + value.map(canonicalize).join(',') + ']';
 *     }
 *     if (t === 'object') {
 *       const obj = value as Record<string, unknown> & { toJSON?: () => unknown };
 *       if (typeof obj.toJSON === 'function') {
 *         try {
 *           const projected = obj.toJSON();
 *           if (projected !== value) return canonicalize(projected);
 *         } catch { }
 *       }
 *       const keys = Object.keys(obj).filter((k) => !EXCLUDED_KEYS.has(k)).sort();
 *       return (
 *         '{' +
 *         keys.map((k) => JSON.stringify(k) + ':' + canonicalize(obj[k])).join(',') +
 *         '}'
 *       );
 *     }
 *     return 'null';
 *   }
 *
 * `CHAIN_PREV_HASH_FIELD` = `'chain_prev_hash'`, `CHAIN_HASH_FIELD` =
 * `'chain_hash'` in the producer (audit-chain-specific field names —
 * unrelated to the bundle/manifest shapes this module canonicalizes, but
 * ported verbatim so the EXCLUDED_KEYS set is byte-identical: a manifest
 * or payload object that happened to carry a `_id`/`chain_prev_hash`/
 * `chain_hash` key would be canonicalized identically by both sides only
 * if both exclude the same keys).
 *
 * Consumer-side use (this repo): `src/engine/keys/verifyCatalogSignature.ts`
 * recomputes the FPS §7.2.3 compact signing payload and the FPS §7.2.2
 * Merkle leaves from an already-downloaded, not-yet-trusted bundle, so this
 * module is imported by a pre-trust-decision code path — it MUST stay pure
 * (no I/O, no throwing on well-formed-but-unexpected input beyond what the
 * ported algorithm itself does) so a malformed value degrades to `'null'`
 * exactly as the producer's own canonicalize does, rather than crashing the
 * verifier on attacker-controlled bytes.
 */

/** Field names excluded from canonical object serialization — ported
 *  verbatim from the producer's `shared/audit-chain.ts` EXCLUDED_KEYS set
 *  (Mongo's `_id` plus the audit hash-chain's own two linkage fields). Kept
 *  under the SAME literal key names for byte-identical canonicalization
 *  parity, even though the bundle/manifest/leaf objects this module
 *  canonicalizes do not carry these fields in normal operation. */
const EXCLUDED_KEYS = new Set<string>(['_id', 'chain_prev_hash', 'chain_hash']);

/**
 * Deterministic JSON serialization — verbatim port of the producer's
 * `canonicalize()` (see module docstring for the exact source bytes).
 * Same inputs produce the same output as the producer's function, which is
 * the property every recomputation in this module depends on.
 */
export function canonicalize(value: unknown): string {
  if (value === null || value === undefined) return 'null';
  if (value instanceof Date) return JSON.stringify(value.toISOString());
  const t = typeof value;
  if (t === 'bigint') return JSON.stringify((value as bigint).toString());
  if (t === 'string' || t === 'number' || t === 'boolean') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalize).join(',') + ']';
  }
  if (t === 'object') {
    // Honor .toJSON() when present (BSON wrapper types in the producer's
    // Mongo-sourced values; ported here for byte-identical parity even
    // though the Chariot side canonicalizes plain JSON.parse() output,
    // which never carries a BSON wrapper's .toJSON).
    const obj = value as Record<string, unknown> & { toJSON?: () => unknown };
    if (typeof obj.toJSON === 'function') {
      try {
        const projected = obj.toJSON();
        if (projected !== value) return canonicalize(projected);
      } catch {
        // toJSON threw — fall through to the generic object handler, same
        // fail-soft behavior as the producer.
      }
    }
    const keys = Object.keys(obj).filter((k) => !EXCLUDED_KEYS.has(k)).sort();
    return (
      '{' +
      keys.map((k) => JSON.stringify(k) + ':' + canonicalize(obj[k])).join(',') +
      '}'
    );
  }
  return 'null';
}
