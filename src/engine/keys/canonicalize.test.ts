/**
 * FPS §7.2.2/§7.2.3 canonical-serializer parity — `canonicalize()` in this
 * repo is a verbatim port of the upstream materializer's
 * `shared/audit-chain.ts:34-84` `canonicalize()` (see
 * `src/engine/keys/canonicalize.ts`'s module docstring for the exact
 * ported source). Every assertion below pins a LITERAL expected string,
 * hand-derived from the ported algorithm's own rules (null/undefined
 * coercion, Date-as-ISO-string, bigint-as-string, key sort, EXCLUDED_KEYS
 * filter, array order preservation, toJSON honoring) — not from running
 * the implementation and copying its output, so a defect in the port would
 * produce a MISMATCH against these pinned strings rather than a
 * self-confirming green test.
 *
 * Run (after tsc): node --test dist/engine/keys/canonicalize.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { canonicalize } from './canonicalize.js';

test('null and undefined both canonicalize to the literal string "null"', () => {
  assert.equal(canonicalize(null), 'null');
  assert.equal(canonicalize(undefined), 'null');
});

test('primitives use JSON.stringify verbatim', () => {
  assert.equal(canonicalize('hello'), '"hello"');
  assert.equal(canonicalize(''), '""');
  assert.equal(canonicalize(42), '42');
  assert.equal(canonicalize(0), '0');
  assert.equal(canonicalize(-3.5), '-3.5');
  assert.equal(canonicalize(true), 'true');
  assert.equal(canonicalize(false), 'false');
});

test('a string containing characters JSON must escape is escaped exactly like JSON.stringify', () => {
  // Hand-derived: JSON.stringify('a"b\nc') === '"a\\"b\\nc"'.
  assert.equal(canonicalize('a"b\nc'), '"a\\"b\\nc"');
});

test('Date renders as its ISO-8601 string, JSON-quoted', () => {
  const d = new Date('2026-01-15T12:00:00.000Z');
  // Hand-derived: d.toISOString() === '2026-01-15T12:00:00.000Z'; JSON.stringify of that string.
  assert.equal(canonicalize(d), '"2026-01-15T12:00:00.000Z"');
});

test('bigint renders as its decimal string, JSON-quoted (not a raw numeric literal)', () => {
  // Hand-derived: (12345678901234567890n).toString() === '12345678901234567890';
  // JSON.stringify of that string wraps it in quotes.
  assert.equal(canonicalize(12345678901234567890n), '"12345678901234567890"');
  assert.equal(canonicalize(0n), '"0"');
});

test('arrays preserve element order — reordering is a different canonical string', () => {
  assert.equal(canonicalize([1, 2, 3]), '[1,2,3]');
  assert.equal(canonicalize([3, 2, 1]), '[3,2,1]');
  assert.notEqual(canonicalize([1, 2, 3]), canonicalize([3, 2, 1]));
  assert.equal(canonicalize([]), '[]');
  assert.equal(canonicalize(['b', 'a', null, undefined]), '["b","a",null,null]');
});

test('object keys are sorted lexicographically regardless of insertion order', () => {
  // Hand-derived: keys {b, a, c} sort to [a, b, c]; each rendered "key":value.
  assert.equal(canonicalize({ b: 1, a: 2, c: 3 }), '{"a":2,"b":1,"c":3}');
  // Same logical object, different insertion order, MUST produce the
  // identical string — this is the whole point of the sort.
  assert.equal(canonicalize({ c: 3, a: 2, b: 1 }), '{"a":2,"b":1,"c":3}');
});

test('nested objects/arrays canonicalize recursively with the same rules at every level', () => {
  // Hand-derived: inner object {y:2,x:1} sorts to {"x":1,"y":2}; outer key
  // "arr" sorts before "obj" ('a' < 'o').
  assert.equal(
    canonicalize({ obj: { y: 2, x: 1 }, arr: [3, 1, 2] }),
    '{"arr":[3,1,2],"obj":{"x":1,"y":2}}',
  );
});

test('EXCLUDED_KEYS (_id, chain_prev_hash, chain_hash) are dropped from object serialization', () => {
  // Hand-derived: of {_id, a, chain_prev_hash, chain_hash, z}, only {a, z}
  // survive the EXCLUDED_KEYS filter, then sort a < z.
  const value = {
    _id: 'mongo-oid-should-not-appear',
    a: 1,
    chain_prev_hash: 'should-not-appear',
    chain_hash: 'should-not-appear',
    z: 2,
  };
  assert.equal(canonicalize(value), '{"a":1,"z":2}');
});

test('an EXCLUDED_KEYS field that is the ONLY field yields an empty object', () => {
  assert.equal(canonicalize({ _id: 'x' }), '{}');
});

test('.toJSON() is honored and its RETURN VALUE is canonicalized recursively', () => {
  // Hand-derived: toJSON returns a plain object {v: 'wrapped'}; that object
  // (not the original wrapper) is what gets canonicalized.
  const wrapper = {
    toJSON() {
      return { v: 'wrapped' };
    },
  };
  assert.equal(canonicalize(wrapper), '{"v":"wrapped"}');
});

test('.toJSON() returning a primitive canonicalizes to that primitive, not an object', () => {
  const wrapper = { toJSON: () => 42 };
  assert.equal(canonicalize(wrapper), '42');
});

test('.toJSON() that throws falls back to the generic object handler (fail-soft, matches the producer)', () => {
  const wrapper = { toJSON: () => { throw new Error('boom'); }, a: 1 };
  // Falls through to the generic path — but `toJSON` IS an own enumerable
  // property of `wrapper` (a function VALUE is a perfectly normal property
  // value; enumerability is about the property descriptor, not the value's
  // type), so Object.keys(wrapper) === ['toJSON', 'a'] and BOTH survive the
  // EXCLUDED_KEYS filter (verified independently: `Object.keys({toJSON:
  // ()=>{}, a:1})` === `['toJSON','a']`). Sorted: ['a', 'toJSON'].
  // canonicalize(wrapper.a) === '1'. canonicalize(wrapper.toJSON) —
  // wrapper.toJSON is itself a function VALUE, which is not
  // null/undefined/Date/bigint/string/number/boolean/array/'object'
  // (typeof a function is 'function') — falls through every branch to the
  // final `return 'null'`, so the entry renders unquoted `"toJSON":null`.
  assert.equal(canonicalize(wrapper), '{"a":1,"toJSON":null}');
});

test('.toJSON() returning the SAME reference (identity) is treated as non-recursive to avoid an infinite loop', () => {
  // Ported condition is `if (projected !== value) return canonicalize(projected)`
  // — when toJSON returns `this` (or otherwise ===-equal to the input), the
  // function falls through to the generic object handler instead of
  // recursing forever. toJSON itself is excluded from the generic handler's
  // enumerable-key walk (it's a function value skipped implicitly only in
  // the sense that Object.keys includes it as a key here since it's a
  // normal property — so we assert the actual literal contract instead:
  // Object.keys(obj) on a plain object WITH an own toJSON function DOES
  // include 'toJSON' as a key, and canonicalize(obj['toJSON']) canonicalizes
  // a function value, which is not null/undefined/Date/bigint/string/
  // number/boolean/array/'object' (typeof a function is 'function') -> falls
  // to the final `return 'null'`.
  const self: { a: number; toJSON: () => unknown } = {
    a: 1,
    toJSON() {
      return self;
    },
  };
  assert.equal(canonicalize(self), '{"a":1,"toJSON":null}');
});

test('a bare function value (typeof "function", not object/primitive/array) canonicalizes to "null"', () => {
  assert.equal(canonicalize(() => 1), 'null');
});

test('symbol values canonicalize to "null" (typeof "symbol" falls through every branch)', () => {
  assert.equal(canonicalize(Symbol('x')), 'null');
});

test('a value with an undefined property drops that key from the object output (matches JSON.stringify semantics via the recursive "null" coercion is NOT what happens — the key survives with value null)', () => {
  // canonicalize does NOT delete keys with an undefined value the way
  // JSON.stringify does — Object.keys still enumerates the key, and
  // canonicalize(undefined) === 'null', so the key survives as `"k":null`.
  assert.equal(canonicalize({ k: undefined }), '{"k":null}');
});

test('FPS §7.2.2 leaf shape: canonicalize({ array, id, publishHash }) hand-derived', () => {
  const leaf = { array: 'catalog', id: 'adapter-a', publishHash: 'a'.repeat(64) };
  assert.equal(
    canonicalize(leaf),
    `{"array":"catalog","id":"adapter-a","publishHash":"${'a'.repeat(64)}"}`,
  );
});

test('FPS §7.2.3 compact payload shape: canonicalize({ manifestHash, merkleRoot, epoch, catalogVersion }) hand-derived, key order in the source object does not matter', () => {
  const payload = {
    catalogVersion: 3,
    epoch: 1700000000000,
    manifestHash: 'b'.repeat(64),
    merkleRoot: 'c'.repeat(64),
  };
  // Sorted keys: catalogVersion, epoch, manifestHash, merkleRoot.
  assert.equal(
    canonicalize(payload),
    `{"catalogVersion":3,"epoch":1700000000000,"manifestHash":"${'b'.repeat(64)}","merkleRoot":"${'c'.repeat(64)}"}`,
  );
});
