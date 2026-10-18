/**
 * CHARIOT::§12.2::11 — binding-aware forbid on dynamic/computed access to
 * the crypto module surface.
 *
 * The name-based `no-restricted-syntax` selectors this rule replaces
 * (`object.name=/^(crypto|webcrypto|subtle)$/`) miss a repo-legal alias:
 *
 *   import * as c from 'node:crypto';
 *   const p = 'hkdf' + 'Sync';
 *   export function derive(root, salt, info) {
 *     return c[p]('sha256', root, salt, info, 32);
 *   }
 *
 * — no literal `crypto`/`webcrypto`/`subtle` identifier anywhere, so the
 * name-based selector never matches, even though `c` IS the crypto module.
 * This rule tracks every LOCAL BINDING that resolves to the crypto module
 * object or one of its `subtle`/`webcrypto` sub-objects (however it was
 * imported/required/aliased/destructured), then forbids:
 *
 *   (a) any COMPUTED member access (`x[...]`) whose object is such a
 *       binding or a `.subtle`/`.webcrypto` member chain off one;
 *   (b) `Reflect.get`/`Reflect.apply`/`Reflect.ownKeys` with such a
 *       binding (or chain) as an argument;
 *   (c) `Function.prototype.call`/`.apply`/`.bind` invoked on a COMPUTED
 *       member of such a binding (`x[p].call(x, ...)`).
 *
 * Binding tracking is a single forward pass over `ImportDeclaration` and
 * `VariableDeclarator` nodes (import/require/`await import(...)`, plain
 * destructuring, and `.subtle`/`.webcrypto` re-binding), so it assumes
 * declaration-before-use — true for every import and for every real
 * call site in this codebase. `globalThis.crypto` (and its `.subtle`/
 * `.webcrypto`) is recognized structurally, needing no import at all.
 *
 * Every ENTERPRISE_MASTER_KEY consumer MUST be listed in
 * src/iam/masterKeyConsumers.ts (MASTER_KEY_CONSUMERS / DOCUMENTED_
 * DELEGATORS) — a computed/Reflect/call-indirection lookup on the crypto
 * surface is refused outright rather than trusted to the (best-effort,
 * necessarily incomplete) static scan in masterKeyConsumers.test.ts.
 */

const CRYPTO_MODULE_SPECIFIERS = new Set(['crypto', 'node:crypto']);
const SUB_OBJECT_NAMES = new Set(['subtle', 'webcrypto']);
const REFLECT_METHODS = new Set(['get', 'apply', 'ownKeys']);
const FUNCTION_INDIRECTION_METHODS = new Set(['call', 'apply', 'bind']);

const MESSAGE =
  'src/iam/masterKeyConsumers.ts: computed/Reflect/call-indirection access to the crypto module surface is forbidden — it would bypass the static KDF-consumer scan. Use a plain `.propertyName` member access and call the method directly so the identifier is visible to source review and to the scanner.';

/** @type {import('eslint').Rule.RuleModule} */
export default {
  meta: {
    type: 'problem',
    docs: {
      description:
        'Forbid computed/dynamic (bracket, Reflect, or call/apply/bind indirection) access to any binding derived from the crypto module — bypasses src/iam/masterKeyConsumers.ts\'s static KDF-consumer scan.',
    },
    schema: [],
    messages: {
      computedAccess: MESSAGE,
      reflectAccess: MESSAGE,
      functionIndirection: MESSAGE,
    },
  },
  create(context) {
    /** Local names bound to the crypto module object itself (namespace/default import, `require(...)`, `await import(...)`). */
    const cryptoModuleNames = new Set();
    /** Local names bound to a `subtle`/`webcrypto` sub-object of the crypto module (however reached). */
    const cryptoSubNames = new Set();

    function markObjectPatternAsCryptoModule(pattern) {
      for (const prop of pattern.properties) {
        if (prop.type !== 'Property') continue; // skip RestElement
        const keyName = prop.key && (prop.key.name ?? prop.key.value);
        const value = prop.value;
        if (!value || value.type !== 'Identifier') continue; // skip nested destructuring
        if (keyName === 'subtle' || keyName === 'webcrypto') {
          cryptoSubNames.add(value.name);
        }
        // Other destructured names (e.g. `hkdfSync`) are function bindings,
        // not object/namespace bindings — a plain call on them is caught by
        // the identifier-based static scan, not this structural rule.
      }
    }

    /**
     * Strip TypeScript-only wrapper nodes (`as`/`satisfies`/`!` non-null
     * assertion, and redundant parens) that carry no runtime meaning, so
     * `(c as any)[p]` and `(c!)[p]` are recognized exactly like `c[p]` —
     * a cast is not an evasion of what object is actually being indexed.
     */
    function unwrapTsCast(expr) {
      let current = expr;
      while (
        current &&
        (current.type === 'TSAsExpression' ||
          current.type === 'TSSatisfiesExpression' ||
          current.type === 'TSNonNullExpression' ||
          current.type === 'TSTypeAssertion')
      ) {
        current = current.expression;
      }
      return current;
    }

    function isGlobalThisCrypto(expr) {
      return (
        expr.type === 'MemberExpression' &&
        !expr.computed &&
        expr.object.type === 'Identifier' &&
        expr.object.name === 'globalThis' &&
        expr.property.type === 'Identifier' &&
        expr.property.name === 'crypto'
      );
    }

    /** True iff `expr` statically resolves to the crypto module object or a `subtle`/`webcrypto` sub-object of it. */
    function isCryptoDerived(exprInput) {
      const expr = unwrapTsCast(exprInput);
      if (!expr) return false;
      if (expr.type === 'Identifier') {
        return cryptoModuleNames.has(expr.name) || cryptoSubNames.has(expr.name);
      }
      if (expr.type === 'MemberExpression' && !expr.computed && expr.property.type === 'Identifier') {
        const propName = expr.property.name;
        const object = unwrapTsCast(expr.object);
        if (isGlobalThisCrypto(expr)) return true;
        // globalThis.crypto.subtle / globalThis.crypto.webcrypto
        if (object && isGlobalThisCrypto(object) && SUB_OBJECT_NAMES.has(propName)) return true;
        // X.subtle / X.webcrypto, X a tracked crypto-module binding
        if (
          object &&
          object.type === 'Identifier' &&
          cryptoModuleNames.has(object.name) &&
          SUB_OBJECT_NAMES.has(propName)
        ) {
          return true;
        }
        // Y.subtle / Y.webcrypto where Y is itself already a tracked sub-object
        // (defensive — real crypto module shape has no such nesting today).
        if (object && object.type === 'Identifier' && cryptoSubNames.has(object.name) && SUB_OBJECT_NAMES.has(propName)) {
          return true;
        }
      }
      return false;
    }

    return {
      ImportDeclaration(node) {
        const specifierValue = typeof node.source.value === 'string' ? node.source.value : null;
        if (!specifierValue || !CRYPTO_MODULE_SPECIFIERS.has(specifierValue)) return;
        for (const spec of node.specifiers) {
          if (spec.type === 'ImportNamespaceSpecifier' || spec.type === 'ImportDefaultSpecifier') {
            // import * as c from 'node:crypto';  /  import crypto from 'node:crypto';
            cryptoModuleNames.add(spec.local.name);
          } else if (spec.type === 'ImportSpecifier') {
            const importedName = spec.imported && (spec.imported.name ?? spec.imported.value);
            if (importedName && SUB_OBJECT_NAMES.has(importedName)) {
              // import { subtle as S, webcrypto as W } from 'node:crypto';
              cryptoSubNames.add(spec.local.name);
            }
            // Other named imports (e.g. `hkdfSync as H`) are function
            // bindings — see markObjectPatternAsCryptoModule's note above.
          }
        }
      },
      VariableDeclarator(node) {
        const init = node.init;
        if (!init) return;

        // const c = require('node:crypto'|'crypto');
        if (
          init.type === 'CallExpression' &&
          init.callee.type === 'Identifier' &&
          init.callee.name === 'require' &&
          init.arguments.length === 1 &&
          init.arguments[0].type === 'Literal' &&
          typeof init.arguments[0].value === 'string' &&
          CRYPTO_MODULE_SPECIFIERS.has(init.arguments[0].value)
        ) {
          if (node.id.type === 'Identifier') cryptoModuleNames.add(node.id.name);
          else if (node.id.type === 'ObjectPattern') markObjectPatternAsCryptoModule(node.id);
          return;
        }

        // const c = await import('node:crypto'|'crypto');
        const importExpr = init.type === 'AwaitExpression' ? init.argument : init;
        if (
          importExpr &&
          importExpr.type === 'ImportExpression' &&
          importExpr.source &&
          importExpr.source.type === 'Literal' &&
          typeof importExpr.source.value === 'string' &&
          CRYPTO_MODULE_SPECIFIERS.has(importExpr.source.value)
        ) {
          if (node.id.type === 'Identifier') cryptoModuleNames.add(node.id.name);
          else if (node.id.type === 'ObjectPattern') markObjectPatternAsCryptoModule(node.id);
          return;
        }

        // const s = c.subtle;  /  const s = c.webcrypto;  (c already tracked)
        if (
          init.type === 'MemberExpression' &&
          !init.computed &&
          init.property.type === 'Identifier' &&
          SUB_OBJECT_NAMES.has(init.property.name) &&
          node.id.type === 'Identifier' &&
          (isCryptoDerived(init.object) || isGlobalThisCrypto(init.object))
        ) {
          cryptoSubNames.add(node.id.name);
          return;
        }

        // const { subtle: S } = c;  (c already tracked as a crypto module binding)
        if (node.id.type === 'ObjectPattern' && (init.type === 'Identifier' ? isCryptoDerived(init) : false)) {
          markObjectPatternAsCryptoModule(node.id);
        }
      },
      'MemberExpression[computed=true]'(node) {
        if (isCryptoDerived(node.object)) {
          context.report({ node, messageId: 'computedAccess' });
        }
      },
      CallExpression(node) {
        const callee = node.callee;
        if (callee.type !== 'MemberExpression' || callee.computed || callee.property.type !== 'Identifier') return;

        // Reflect.get(c, ...) / Reflect.apply(fn, c, ...) / Reflect.ownKeys(c)
        if (
          callee.object.type === 'Identifier' &&
          callee.object.name === 'Reflect' &&
          REFLECT_METHODS.has(callee.property.name)
        ) {
          const targetsCrypto = node.arguments.some((arg) => isCryptoDerived(arg));
          if (targetsCrypto) {
            context.report({ node, messageId: 'reflectAccess' });
          }
          return;
        }

        // x[p].call(...) / x[p].apply(...) / x[p].bind(...), x crypto-derived
        if (
          FUNCTION_INDIRECTION_METHODS.has(callee.property.name)
        ) {
          const calleeObject = unwrapTsCast(callee.object);
          if (calleeObject && calleeObject.type === 'MemberExpression' && calleeObject.computed && isCryptoDerived(calleeObject.object)) {
            context.report({ node, messageId: 'functionIndirection' });
          }
        }
      },
    };
  },
};
