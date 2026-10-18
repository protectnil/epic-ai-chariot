/**
 * CHARIOT::§12.2::11 — RuleTester coverage for eslint-rules/no-dynamic-
 * module-specifier.js.
 *
 * Not `.ts` under `src/` for the same reason as
 * no-dynamic-crypto-access.test.mjs: tsconfig.json's `rootDir`/`include`
 * is `src/**\/*.ts` only, so a `.ts` file here would never reach `dist/`
 * for `node --test dist/...` to run.
 *
 * Gate finding closed (thread naming this unit):
 *
 *   const spec = 'node:' + 'crypto';
 *   const c = await import(spec);
 *   c[p](...);
 *
 * — `local/no-dynamic-crypto-access`'s binding tracker only marks a
 * binding as "crypto module" when the import()/require() specifier is a
 * plain string literal, so a non-literal specifier (concatenation, a
 * variable, a template with interpolation) defeats it by construction —
 * no amount of smarter tracking fixes that, since the specifier is
 * genuinely not statically known. This rule instead forbids the
 * non-literal specifier itself, everywhere, so the tracker's literal-only
 * assumption is sound.
 *
 * Run: node --test eslint-rules/no-dynamic-module-specifier.test.mjs
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { RuleTester } from 'eslint';
import rule from './no-dynamic-module-specifier.js';

const ruleTester = new RuleTester({
  languageOptions: { ecmaVersion: 'latest', sourceType: 'module' },
});

test('no-dynamic-module-specifier: RuleTester valid/invalid corpus', () => {
  ruleTester.run('no-dynamic-module-specifier', rule, {
    valid: [
      // Plain string literal specifiers — the normal, auditable form.
      { code: "import('node:crypto');" },
      { code: "require('node:crypto');" },
      { code: "import('some-unrelated-package');" },
      { code: "require('some-unrelated-package');" },
      // Template literal with NO interpolation — statically known, same as a literal.
      { code: "import(`node:crypto`);" },
      { code: "require(`node:crypto`);" },
      // createRequire(...) used with a literal specifier, both curried and via a binding.
      { code: "import { createRequire } from 'node:module'; createRequire(import.meta.url)('node:crypto');" },
      { code: "import { createRequire } from 'node:module'; const req = createRequire(import.meta.url); req('node:crypto');" },
      // module.require with a literal specifier.
      { code: "module.require('node:crypto');" },
      // A top-level `const NAME = '<literal>';` binding referenced at the
      // call site — this codebase's own idiom (chainSigner.ts's
      // KMS_SDK_MODULE_ID, license-manager.ts's SDK_MODULE_ID) is exactly
      // as static as the literal itself.
      { code: "const MOD = 'node:crypto'; import(MOD);" },
      { code: "const MOD = 'node:crypto'; require(MOD);" },
      { code: "const MOD = `node:crypto`; import(MOD);" },
      // A `let`/reassignable binding with the SAME initial value is NOT
      // tracked — only `const` gives the "cannot change" guarantee.
      // (kept as an INVALID case below, not here, to prove the rule
      // still fires on it.)
      // A call to a function that happens to be named 'require' is fine —
      // wait: no, bare `require(...)` is always checked regardless of
      // where it's defined (Node's require IS a bare identifier call) —
      // this valid case instead covers an UNRELATED function that takes
      // one non-string argument, proving the rule doesn't false-positive
      // on arbitrary calls.
      { code: "function process(x) {} process(42);" },
      { code: "function process(x) {} const y = 1; process(y);" },
    ],
    invalid: [
      // The gate's exact evasion (import() with a variable specifier).
      {
        code: "async function f(){ const spec = 'node:' + 'crypto'; const c = await import(spec); }",
        errors: [{ messageId: 'dynamicSpecifier' }],
      },
      // require(name) — a plain variable.
      {
        code: "function f(name) { return require(name); }",
        errors: [{ messageId: 'dynamicSpecifier' }],
      },
      // Template literal WITH interpolation.
      {
        code: "function f(x) { return import(`node:${x}`); }",
        errors: [{ messageId: 'dynamicSpecifier' }],
      },
      // String concatenation directly in the call.
      {
        code: "async function f(x){ return import('node:' + x); }",
        errors: [{ messageId: 'dynamicSpecifier' }],
      },
      // createRequire(...)(x), curried, non-literal.
      {
        code: "import { createRequire } from 'node:module'; function f(spec) { return createRequire(import.meta.url)(spec); }",
        errors: [{ messageId: 'dynamicSpecifier' }],
      },
      // req(x) via a createRequire(...)-bound variable, non-literal.
      {
        code: "import { createRequire } from 'node:module'; const req = createRequire(import.meta.url); function f(spec) { return req(spec); }",
        errors: [{ messageId: 'dynamicSpecifier' }],
      },
      // module.require(x), non-literal.
      {
        code: "function f(spec) { return module.require(spec); }",
        errors: [{ messageId: 'dynamicSpecifier' }],
      },
      // A `let` binding is reassignable — even with a literal INITIAL
      // value, it is NOT tracked as static (only `const` is).
      {
        code: "let mod = 'node:crypto'; import(mod);",
        errors: [{ messageId: 'dynamicSpecifier' }],
      },
    ],
  });
  assert.ok(true, 'RuleTester.run completed without throwing');
});

test('no-dynamic-module-specifier: TS-cast forms (parsed with @typescript-eslint/parser)', async () => {
  const tsParser = (await import('@typescript-eslint/parser')).default;
  const tsRuleTester = new RuleTester({
    languageOptions: { ecmaVersion: 'latest', sourceType: 'module', parser: tsParser },
  });
  tsRuleTester.run('no-dynamic-module-specifier', rule, {
    valid: [
      // A TS cast on an otherwise-static specifier carries no runtime
      // meaning and must not defeat staticness — this is renew-client.ts's
      // real `import(... 'undici' as string)` shape.
      { code: "import('node:crypto' as string);" },
      { code: "const MOD = 'node:crypto'; import(MOD as string);" },
      { code: "import('node:crypto'!);" },
    ],
    invalid: [
      // A cast does not make a genuinely dynamic specifier static either.
      {
        code: "function f(spec: string) { return import(spec as string); }",
        errors: [{ messageId: 'dynamicSpecifier' }],
      },
    ],
  });
  assert.ok(true, 'TS-parser RuleTester.run completed without throwing');
});
