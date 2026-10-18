/**
 * CHARIOT::§12.2::11 — forbid a non-literal module specifier on any dynamic
 * `import()`/`require()` form, repo-wide.
 *
 * Closes the root cause behind two prior findings against
 * `local/no-dynamic-crypto-access`'s binding tracker: that rule only marks
 * a binding as "crypto module" when the `import()`/`require()` specifier is
 * a plain string literal — so it necessarily misses
 *
 *   const spec = 'node:' + 'crypto';
 *   const c = await import(spec);
 *   c[p](...); // p itself dynamic too, but irrelevant here
 *
 * because `spec` is not statically a `'node:crypto'` literal at all. No
 * amount of smarter binding tracking closes this — a module specifier
 * built from string concatenation, a variable, a function call, etc. is
 * NOT statically resolvable in general (that's what makes CommonJS/ESM
 * dynamic specifiers dynamic). The only sound fix is to forbid the
 * NON-LITERAL specifier itself, everywhere, so `local/no-dynamic-crypto-
 * access`'s literal-only tracking is complete BY CONSTRUCTION: every
 * `import()`/`require()` specifier this codebase is allowed to write is
 * one that rule can already see.
 *
 * Reports:
 *   - `import(x)` (dynamic import expression) where `x` is not statically
 *     known — see `isStaticExpression` below;
 *   - `require(x)` (bare `require`) under the same rule;
 *   - `createRequire(...)(x)` (the curried Node `module` API form), and a
 *     call through a binding assigned from `createRequire(...)`;
 *   - `module.require(x)` (the CommonJS-interop member form).
 *
 * "Statically known" (`isStaticExpression`) accepts:
 *   - a string Literal, or a template literal with ZERO `${...}`
 *     expressions — the specifier text itself;
 *   - a reference to a top-level `const NAME = <one of the above>;`
 *     binding — `const` cannot be reassigned, so a named module-id
 *     constant (this codebase's own idiom, e.g. `chainSigner.ts`'s
 *     `const KMS_SDK_MODULE_ID = '@aws-sdk/client-kms';`) is exactly as
 *     statically known as writing the literal inline, and forcing every
 *     call site to inline it would only hurt readability for zero
 *     auditability gain;
 *   - either of the above wrapped in a TypeScript `as`/`satisfies`/`!`
 *     cast (`'undici' as string`) — a cast carries no runtime meaning, so
 *     it must not change whether the underlying expression is static.
 */

const STATIC_TYPE_ERROR =
  'src/iam/masterKeyConsumers.ts: module specifiers must be static (a string literal, a template literal with no `${...}` expressions, or a reference to a top-level `const NAME = <literal>` binding) so every derivation-relevant import()/require() site is statically auditable. Assign the module path to a literal or a const literal binding, not a computed/concatenated/reassignable expression.';

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

function isLiteralOrNoInterpTemplate(node) {
  if (!node) return false;
  if (node.type === 'Literal' && typeof node.value === 'string') return true;
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) return true;
  return false;
}

/** @type {import('eslint').Rule.RuleModule} */
export default {
  meta: {
    type: 'problem',
    docs: {
      description:
        'Forbid a non-literal module specifier on import()/require()/createRequire(...)()/module.require() — required so local/no-dynamic-crypto-access\'s literal-only tracking is complete.',
    },
    schema: [],
    messages: {
      dynamicSpecifier: STATIC_TYPE_ERROR,
    },
  },
  create(context) {
    /** Local names bound to the result of `createRequire(...)` — calling one of these is itself a require-like call. */
    const requireLikeNames = new Set();
    /** Top-level `const NAME = <literal>;` bindings — a reference to one of these is as static as the literal itself. */
    const constLiteralNames = new Set();

    function isStaticExpression(exprInput) {
      const expr = unwrapTsCast(exprInput);
      if (!expr) return false;
      if (isLiteralOrNoInterpTemplate(expr)) return true;
      if (expr.type === 'Identifier' && constLiteralNames.has(expr.name)) return true;
      return false;
    }

    function checkArgument(node) {
      const arg = node.arguments[0];
      if (!isStaticExpression(arg)) {
        context.report({ node, messageId: 'dynamicSpecifier' });
      }
    }

    return {
      VariableDeclarator(node) {
        // const req = createRequire(...);
        if (
          node.init &&
          node.init.type === 'CallExpression' &&
          node.init.callee.type === 'Identifier' &&
          node.init.callee.name === 'createRequire' &&
          node.id.type === 'Identifier'
        ) {
          requireLikeNames.add(node.id.name);
          return;
        }
        // const NAME = '<literal>' | `<no-interp template>`, `const` only
        // (a `let`/`var` binding IS reassignable, so it is NOT tracked —
        // only `const` gives the "cannot change" guarantee this relies on).
        if (
          node.parent &&
          node.parent.type === 'VariableDeclaration' &&
          node.parent.kind === 'const' &&
          node.id.type === 'Identifier' &&
          isLiteralOrNoInterpTemplate(unwrapTsCast(node.init))
        ) {
          constLiteralNames.add(node.id.name);
        }
      },
      ImportExpression(node) {
        if (!isStaticExpression(node.source)) {
          context.report({ node, messageId: 'dynamicSpecifier' });
        }
      },
      CallExpression(node) {
        const callee = node.callee;

        // require(x)
        if (callee.type === 'Identifier' && callee.name === 'require') {
          checkArgument(node);
          return;
        }

        // req(x), req bound from createRequire(...) above
        if (callee.type === 'Identifier' && requireLikeNames.has(callee.name)) {
          checkArgument(node);
          return;
        }

        // createRequire(...)(x) — curried, called directly with no
        // intermediate binding.
        if (
          callee.type === 'CallExpression' &&
          callee.callee.type === 'Identifier' &&
          callee.callee.name === 'createRequire'
        ) {
          checkArgument(node);
          return;
        }

        // module.require(x)
        if (
          callee.type === 'MemberExpression' &&
          !callee.computed &&
          callee.object.type === 'Identifier' &&
          callee.object.name === 'module' &&
          callee.property.type === 'Identifier' &&
          callee.property.name === 'require'
        ) {
          checkArgument(node);
        }
      },
    };
  },
};
