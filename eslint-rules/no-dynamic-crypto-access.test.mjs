/**
 * CHARIOT::§12.2::11 — RuleTester coverage for eslint-rules/no-dynamic-
 * crypto-access.js (the binding-aware structural closure over the four
 * name-based `no-restricted-syntax` selectors it replaces).
 *
 * NOT a `.ts` file under `src/`: tsconfig.json's `rootDir`/`include` is
 * `src/**\/*.ts` only (native/, eslint-rules/, etc. are outside it), so a
 * `.ts` file here would never reach `dist/` for `node --test dist/...` to
 * run — the repo's OWN existing `test/*.mjs` files follow the same
 * no-compile pattern for exactly this reason. This file mirrors that
 * convention: plain `.mjs`, run directly (registered in
 * scripts/run-all-tests.mjs), no build step.
 *
 * Gate finding closed (thread naming this unit): the four name-based
 * selectors this rule replaces matched only the LITERAL identifiers
 * `crypto`/`webcrypto`/`subtle`, so a repo-legal alias defeated them:
 *
 *   import * as c from 'node:crypto';
 *   const p = 'hkdf' + 'Sync';
 *   export function derive(root, salt, info) {
 *     return c[p]('sha256', root, salt, info, 32);
 *   }
 *
 * — used verbatim below as the first invalid case. The rule instead
 * tracks every LOCAL BINDING that resolves to the crypto module object or
 * a `subtle`/`webcrypto` sub-object of it (import namespace/default,
 * `require(...)`, `await import(...)`, destructuring, and `.subtle`/
 * `.webcrypto` re-binding), then forbids computed member access, `Reflect.
 * get`/`apply`/`ownKeys`, and `.call`/`.apply`/`.bind` indirection on any
 * of them — `globalThis.crypto` needs no import at all and is recognized
 * structurally.
 *
 * Run: node --test eslint-rules/no-dynamic-crypto-access.test.mjs
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { RuleTester } from 'eslint';
import tsParser from '@typescript-eslint/parser';
import rule from './no-dynamic-crypto-access.js';

const ruleTester = new RuleTester({
  languageOptions: { ecmaVersion: 'latest', sourceType: 'module' },
});

// Separate RuleTester instance using the TS parser this repo actually lints
// with (eslint.config.js: `...tseslint.configs.recommended`) — proves the
// `(c as any)[p]`/`(crypto!)[p]` TS-cast forms are unwrapped correctly.
// A real `(c as any)[p]` fixture linted end-to-end through the actual
// eslint.config.js (not just RuleTester) is how this was actually found:
// the first version of this rule checked `node.object.type === 'Identifier'`
// directly and silently missed it, because `as any` wraps the object in a
// `TSAsExpression` node the plain check never saw through.
const tsRuleTester = new RuleTester({
  languageOptions: { ecmaVersion: 'latest', sourceType: 'module', parser: tsParser },
});

test('no-dynamic-crypto-access: RuleTester valid/invalid corpus', () => {
  // RuleTester.run() throws synchronously on any case mismatch; a clean
  // return means every valid/invalid case below passed exactly as
  // specified (message id AND, where given, error count/order).
  ruleTester.run('no-dynamic-crypto-access', rule, {
    valid: [
      // Plain, directly-named member access — the normal, reviewable form.
      { code: "import crypto from 'node:crypto'; crypto.hkdfSync('sha256', a, b, c, 32);" },
      { code: "import * as crypto from 'node:crypto'; crypto.subtle.deriveBits(p, k, 256);" },
      // Unrelated computed access on an unrelated object — must NOT be flagged.
      { code: "const x = {}; const k = 'a'; x[k];" },
      { code: "const arr = [1, 2, 3]; const i = 0; arr[i];" },
      // A plain (non-computed) call reference to a destructured function —
      // caught by the identifier-based static scan, not this structural rule.
      { code: "import crypto from 'node:crypto'; const h = crypto.hkdfSync; h('sha256', a, b, c, 32);" },
      // A crypto-shaped import with only a NAMED (non-subtle/webcrypto)
      // binding used in a computed access elsewhere — the binding itself
      // was never marked crypto-derived (it's a function reference, not
      // the module object), so bracket access on IT is not flagged
      // (there is nothing meaningful to look up on a function this way,
      // and it does not defeat the KDF-consumer scan the way indexing the
      // module object does).
      { code: "import { hkdfSync } from 'node:crypto'; const k = 'name'; hkdfSync[k];" },
      // Reflect used on something unrelated to crypto.
      { code: "const obj = {}; Reflect.get(obj, 'x');" },
      // .call/.apply/.bind on an unrelated computed member.
      { code: "const x = {}; const k = 'f'; x[k].call(x);" },
    ],
    invalid: [
      // The gate's exact evasion: namespace-import alias, string-concat key.
      {
        code: "import * as c from 'node:crypto'; const p = 'hkdf' + 'Sync'; export function derive(root, salt, info){ return c[p]('sha256', root, salt, info, 32); }",
        errors: [{ messageId: 'computedAccess' }],
      },
      // Default import alias.
      {
        code: "import crypto from 'node:crypto'; const k = 'hkdfSync'; crypto[k]();",
        errors: [{ messageId: 'computedAccess' }],
      },
      // require(...) alias.
      {
        code: "const crypto = require('node:crypto'); const k = 'hkdfSync'; crypto[k]();",
        errors: [{ messageId: 'computedAccess' }],
      },
      // await import(...) alias.
      {
        code: "async function f(){ const c = await import('node:crypto'); const k='hkdfSync'; c[k](); }",
        errors: [{ messageId: 'computedAccess' }],
      },
      // Named `subtle` import, aliased.
      {
        code: "import { subtle as S } from 'node:crypto'; const k = 'deriveBits'; S[k]();",
        errors: [{ messageId: 'computedAccess' }],
      },
      // Destructured `subtle` from a tracked module binding.
      {
        code: "import crypto from 'node:crypto'; const { subtle: S } = crypto; const k = 'deriveBits'; S[k]();",
        errors: [{ messageId: 'computedAccess' }],
      },
      // Re-bound `.subtle` member access (`const s = crypto.subtle`).
      {
        code: "import crypto from 'node:crypto'; const s = crypto.subtle; const k = 'deriveBits'; s[k]();",
        errors: [{ messageId: 'computedAccess' }],
      },
      // globalThis.crypto — no import at all.
      {
        code: "const k = 'hkdfSync'; globalThis.crypto[k]();",
        errors: [{ messageId: 'computedAccess' }],
      },
      // globalThis.crypto.subtle, re-bound.
      {
        code: "const k = 'deriveBits'; const s = globalThis.crypto.subtle; s[k]();",
        errors: [{ messageId: 'computedAccess' }],
      },
      // Reflect.get on the module binding.
      {
        code: "import crypto from 'node:crypto'; const k = 'hkdfSync'; Reflect.get(crypto, k)();",
        errors: [{ messageId: 'reflectAccess' }],
      },
      // Reflect.apply whose second (thisArg) argument is the module binding,
      // with a computed member as the function argument (fires both).
      {
        code: "import crypto from 'node:crypto'; const k = 'hkdfSync'; Reflect.apply(crypto[k], crypto, []);",
        errors: [{ messageId: 'reflectAccess' }, { messageId: 'computedAccess' }],
      },
      // Reflect.ownKeys on the module binding.
      {
        code: "import crypto from 'node:crypto'; Reflect.ownKeys(crypto);",
        errors: [{ messageId: 'reflectAccess' }],
      },
      // Function.prototype.call indirection through a computed member —
      // fires functionIndirection (outer call, visited on enter) AND
      // computedAccess (the inner bracket access itself).
      {
        code: "import crypto from 'node:crypto'; const k = 'hkdfSync'; crypto[k].call(crypto, 'sha256');",
        errors: [{ messageId: 'functionIndirection' }, { messageId: 'computedAccess' }],
      },
    ],
  });
  assert.ok(true, 'RuleTester.run completed without throwing');
});

test('no-dynamic-crypto-access: TS-cast forms (parsed with @typescript-eslint/parser, the repo\'s real parser)', () => {
  tsRuleTester.run('no-dynamic-crypto-access', rule, {
    valid: [
      { code: "import crypto from 'node:crypto'; export function derive(root: Buffer, salt: Buffer, info: Buffer): Buffer { return Buffer.from(crypto.hkdfSync('sha256', root, salt, info, 32)); }" },
    ],
    invalid: [
      // `as any` cast on the object side of a computed access — must be
      // unwrapped, not treated as opaque.
      {
        code: "import * as c from 'node:crypto'; const p: string = 'hkdf' + 'Sync'; export function derive(root: Buffer, salt: Buffer, info: Buffer) { return (c as any)[p]('sha256', root, salt, info, 32); }",
        errors: [{ messageId: 'computedAccess' }],
      },
      // Non-null assertion (`!`) on the object side.
      {
        code: "import crypto from 'node:crypto'; const k = 'hkdfSync'; (crypto!)[k]();",
        errors: [{ messageId: 'computedAccess' }],
      },
    ],
  });
  assert.ok(true, 'TS-parser RuleTester.run completed without throwing');
});
