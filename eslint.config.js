import js from '@eslint/js';
import globals from 'globals';
import tseslint from 'typescript-eslint';
import noDynamicCryptoAccess from './eslint-rules/no-dynamic-crypto-access.js';
import noDynamicModuleSpecifier from './eslint-rules/no-dynamic-module-specifier.js';

export default [
  {
    ignores: ['dist/**', 'node_modules/**', 'src/engine/mcp-servers/**'],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    languageOptions: {
      parserOptions: {
        project: false,
      },
    },
    // CHARIOT::§12.2::11 — 'local' is this repo's own eslint-rules/ directory,
    // loaded as an in-repo flat-config plugin (no npm package). See
    // eslint-rules/no-dynamic-crypto-access.js for the rule and
    // eslint-rules/no-dynamic-crypto-access.test.mjs for its RuleTester
    // corpus (registered in scripts/run-all-tests.mjs).
    plugins: {
      local: {
        rules: {
          'no-dynamic-crypto-access': noDynamicCryptoAccess,
          'no-dynamic-module-specifier': noDynamicModuleSpecifier,
        },
      },
    },
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      '@typescript-eslint/no-non-null-assertion': 'off',
      '@typescript-eslint/no-empty-object-type': 'off',
      '@typescript-eslint/no-namespace': 'off',
      'no-empty': ['error', { allowEmptyCatch: true }],
      'no-control-regex': 'off',
      'no-useless-escape': 'warn',
      // CHARIOT::§12.2::11 — eval-family code-from-string execution
      // (`eval(...)`, `setTimeout('...')`/`setInterval('...')` string
      // bodies, `new Function(...)`) is a further way to obtain and call a
      // KDF-family function outside any AST shape the scanner or the two
      // local rules below can see. Not previously enabled in this config.
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      // CHARIOT::§12.2::11 — every import()/require() specifier in this
      // codebase MUST be statically literal (or a no-interpolation
      // template) so `local/no-dynamic-crypto-access`'s binding tracker
      // — which only recognizes a LITERAL 'node:crypto'/'crypto' specifier
      // — is complete by construction: a specifier built from
      // concatenation, a variable, or any other non-literal expression
      // (`import('node:' + 'crypto')`, `import(spec)`) is forbidden
      // outright rather than left for that tracker to (necessarily) miss.
      'local/no-dynamic-module-specifier': 'error',
      // CHARIOT::§12.2::11 — a computed-property, Reflect-based, or
      // call/apply/bind-indirected lookup on the crypto surface
      // (`crypto['hkdfSync']`, `Reflect.get(crypto, 'hkdfSync')`,
      // `crypto[k].call(crypto, ...)`) can obtain a KDF-family function
      // through the SAME capability the static analysis in
      // src/iam/masterKeyConsumers.test.ts scans for, without ever
      // spelling the property name as a normal member access. Every
      // ENTERPRISE_MASTER_KEY consumer MUST be listed in
      // src/iam/masterKeyConsumers.ts (MASTER_KEY_CONSUMERS /
      // DOCUMENTED_DELEGATORS) — this indirection is refused outright
      // rather than trusted to the (best-effort) scanner.
      //
      // Was 4 name-based `no-restricted-syntax` selectors matching only the
      // LITERAL identifiers `crypto`/`webcrypto`/`subtle` — defeated by a
      // repo-legal alias (`import * as c from 'node:crypto'; c[k]()`), since
      // an AST selector cannot itself track which local binding an import
      // produced. `local/no-dynamic-crypto-access` is BINDING-AWARE (it
      // tracks every import/require/destructure/re-bind form that resolves
      // to the crypto module or a subtle/webcrypto sub-object of it) and
      // fully subsumes all four selectors — including their `globalThis.
      // crypto` case — so they are removed rather than kept alongside it.
      'local/no-dynamic-crypto-access': 'error',
    },
  },
  {
    // Node-run JavaScript outside src/ (the test roll-call runner, the local
    // eslint rules and this config) executes under Node: give it the Node
    // globals so `process`/`console` are not reported as undefined.
    files: ['scripts/**/*.mjs', 'scripts/**/*.js', 'eslint-rules/**/*.js', 'eslint-rules/**/*.mjs', 'eslint.config.js'],
    languageOptions: { globals: { ...globals.node } },
  },
];
