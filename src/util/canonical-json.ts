/**
 * Deterministic JSON serializer for hash-chain inputs.
 *
 * Standard `JSON.stringify` does not guarantee key order across writes —
 * `{a: 1, b: 2}` and `{b: 2, a: 1}` produce different strings even though
 * they are the same logical value. Hashing the result therefore yields
 * different hashes for equal inputs, which silently breaks any tamper-
 * evidence scheme that recomputes the hash and compares to a stored value.
 *
 * `canonicalStringify` produces byte-identical output for any two inputs
 * that are deeply equal as JSON values:
 *   - Object keys are sorted lexicographically (ASCII byte order, locale-
 *     independent) at every nesting level.
 *   - Object entries whose value is `undefined` are dropped (matches
 *     `JSON.stringify` behavior so legacy callers do not produce a
 *     different shape).
 *   - Arrays preserve their order (arrays are ordered by definition).
 *   - Strings are emitted via `JSON.stringify` so escaping is correct.
 *   - Throws on `undefined` at top level or inside arrays, on non-finite
 *     numbers, on `bigint`, on functions, and on symbols. These cases
 *     either cannot round-trip through JSON or produce non-deterministic
 *     output that would defeat the whole purpose of canonicalization.
 *
 * Cycles are not detected; a cyclic input will overflow the call stack.
 * Audit-event metadata round-trips through MongoDB which rejects cycles,
 * so this is acceptable for the calling context.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

export function canonicalStringify(value: unknown): string {
  if (value === null) return 'null';

  // Match JSON.stringify: invoke toJSON() if present (Date, BSON ObjectId,
  // any class that opts in to a serialized form). The result then runs
  // through canonicalStringify itself so nested objects still get sorted.
  if (
    value !== undefined &&
    typeof (value as { toJSON?: unknown }).toJSON === 'function'
  ) {
    return canonicalStringify((value as { toJSON: () => unknown }).toJSON());
  }

  const t = typeof value;

  if (t === 'boolean') return value ? 'true' : 'false';

  if (t === 'number') {
    if (!Number.isFinite(value as number)) {
      throw new TypeError(
        `canonicalStringify: non-finite number (${String(value)}) cannot be canonicalized`,
      );
    }
    return String(value);
  }

  if (t === 'string') {
    return JSON.stringify(value);
  }

  if (t === 'bigint') {
    throw new TypeError('canonicalStringify: bigint is not supported');
  }

  if (t === 'function' || t === 'symbol') {
    throw new TypeError(`canonicalStringify: ${t} is not supported`);
  }

  if (t === 'undefined') {
    throw new TypeError(
      'canonicalStringify: undefined is not supported at top level or inside arrays',
    );
  }

  if (Array.isArray(value)) {
    const parts: string[] = [];
    for (const item of value) {
      parts.push(canonicalStringify(item));
    }
    return '[' + parts.join(',') + ']';
  }

  // Plain object (or class instance — we treat its enumerable own keys as a record).
  // Reflect.ownKeys + getOwnPropertyDescriptor handles `__proto__` as a true
  // own property when present (the JSON.stringify path collapses it), giving
  // canonicalStringify a stable answer for fast-check inputs like
  // `Object.defineProperty(obj, '__proto__', { enumerable: true, value: false })`.
  const obj = value as Record<string, unknown>;
  const allKeys: string[] = [];
  for (const k of Reflect.ownKeys(obj)) {
    if (typeof k !== 'string') continue; // symbols ignored, same as JSON.stringify
    const desc = Object.getOwnPropertyDescriptor(obj, k);
    if (!desc || !desc.enumerable) continue;
    allKeys.push(k);
  }
  allKeys.sort();
  const parts: string[] = [];
  for (const k of allKeys) {
    const v = (Object.getOwnPropertyDescriptor(obj, k) as PropertyDescriptor).value as unknown;
    if (v === undefined) continue;
    parts.push(JSON.stringify(k) + ':' + canonicalStringify(v));
  }
  return '{' + parts.join(',') + '}';
}
