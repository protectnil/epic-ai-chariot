/**
 * CHARIOT::§12.2::11/12 — automated enforcement for the ENTERPRISE_MASTER_KEY
 * domain-separation registry (`masterKeyConsumers.ts`).
 *
 * CHARIOT::§12.2::11 (Inspection): "Every consumer of ENTERPRISE_MASTER_KEY
 * SHALL use a (salt, info) pair that is disjoint from the (salt, info) pair
 * of every other consumer." (CHARIOT-SPEC.md §12.2 "Master-key domain
 * separation (CH-10)")
 *
 * CHARIOT::§12.2::12 (Inspection/constraint): "A consumer of
 * ENTERPRISE_MASTER_KEY whose HKDF-SHA256 salt could equal
 * `tenant:{tenantId}` SHALL NOT use an empty `info` parameter."
 *
 * Failure classes closed here:
 *  - two registry entries sharing a literal salt+info pair;
 *  - a templated salt colliding with a literal or another template by
 *    prefix (e.g. a hypothetical new consumer using salt `tenant:foo`);
 *  - a non-vault consumer whose salt could equal `tenant:{tenantId}` using
 *    empty info (the exact hole §12.2::12 closes);
 *  - registry drift: the salt/info bytes claimed in masterKeyConsumers.ts
 *    no longer match the literal bytes in the cited source file;
 *  - a NEW ENTERPRISE_MASTER_KEY-rooted derivation call site landing in the
 *    repo without a corresponding registry entry — via a comment/string-
 *    stripped, alias-resistant scan (see the "Coverage" section below), not
 *    a purely syntactic whole-file regex.
 *
 * Adversarial-review finding closed: the original coverage scan matched a
 * raw-source regex against the WHOLE file, so it was evadable by a
 * destructured alias
 * (`const { hkdfSync: h } = crypto; h(...)`), an indirect function alias, a
 * `subtle.deriveBits` Web Crypto call, or a renamed Rust `use` alias
 * (`use hkdf::Hkdf as K`) — none of which necessarily contain the exact
 * regex the old scanner matched, or could in principle be hidden inside a
 * comment/string that the old scanner had no way to distinguish from real
 * code. The "Coverage" section below strips comments and string/template
 * literals per language before scanning, widens the token set to the
 * KDF-family identifiers a rename cannot remove from its own binding site,
 * classifies every flagged file's apparent secret root (an unregistered
 * derivation from an unrecognized root is reported as a failure, never
 * silently passed), and is proven against an evasion corpus of string
 * fixtures covering each form named in the finding.
 *
 * Run (after tsc): node --test dist/iam/masterKeyConsumers.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, extname } from 'node:path';

import {
  MASTER_KEY_CONSUMERS,
  TEST_FIXTURE_DERIVERS,
  TEST_FIXTURE_MARKER,
  DOCUMENTED_DELEGATORS as DOCUMENTED_DELEGATORS_LIST,
  type DocumentedDelegator,
  VALIDATION_ONLY_FILES,
  VALIDATION_ONLY_MARKER,
  DYNAMIC_LOADER_SITES,
  type InfoShape,
  type SaltShape,
} from './masterKeyConsumers.js';

const here = dirname(fileURLToPath(import.meta.url));
// dist/iam -> repo root is two levels up from dist/.
const repoRoot = join(here, '..', '..');

// ── Disjointness (§12.2::11) ────────────────────────────────────────────────

function saltsCouldCollide(a: SaltShape, b: SaltShape): boolean {
  // An opaque, caller-supplied salt cannot be proven disjoint from anything
  // by shape alone — conservative "could collide".
  if (a.kind === 'opaque' || b.kind === 'opaque') return true;
  if (a.kind === 'literal' && b.kind === 'literal') return a.value === b.value;
  if (a.kind === 'literal' && b.kind === 'templatePrefix') return a.value.startsWith(b.prefix);
  if (b.kind === 'literal' && a.kind === 'templatePrefix') return b.value.startsWith(a.prefix);
  if (a.kind === 'templatePrefix' && b.kind === 'templatePrefix') {
    return a.prefix.startsWith(b.prefix) || b.prefix.startsWith(a.prefix);
  }
  return true;
}

function infosCouldCollide(a: InfoShape, b: InfoShape): boolean {
  if (a.kind === 'empty' && b.kind === 'empty') return true;
  if (a.kind === 'empty' || b.kind === 'empty') return false; // empty never equals non-empty bytes
  if (a.kind === 'literal' && b.kind === 'literal') return a.value === b.value;
  if (a.kind === 'literal' && b.kind === 'templatePrefix') return a.value.startsWith(b.prefix);
  if (b.kind === 'literal' && a.kind === 'templatePrefix') return b.value.startsWith(a.prefix);
  if (a.kind === 'templatePrefix' && b.kind === 'templatePrefix') {
    return a.prefix.startsWith(b.prefix) || b.prefix.startsWith(a.prefix);
  }
  return true;
}

/** A (salt, info) pair is disjoint from another iff the salts cannot collide
 * OR (they could collide but) the infos cannot collide. */
function pairIsDisjoint(x: MasterKeyConsumer, y: MasterKeyConsumer): boolean {
  if (!saltsCouldCollide(x.salt, y.salt)) return true;
  return !infosCouldCollide(x.info, y.info);
}

type MasterKeyConsumer = (typeof MASTER_KEY_CONSUMERS)[number];

test('CHARIOT::§12.2::11 — registry is non-empty (covers the shipped consumers)', () => {
  assert.ok(MASTER_KEY_CONSUMERS.length >= 3, 'expected at least the 3 shipped §12.2 consumers');
});

test('CHARIOT::§12.2::11 — every pair of registered consumers has a disjoint (salt, info) pair', () => {
  const failures: string[] = [];
  for (let i = 0; i < MASTER_KEY_CONSUMERS.length; i++) {
    for (let j = i + 1; j < MASTER_KEY_CONSUMERS.length; j++) {
      const a = MASTER_KEY_CONSUMERS[i]!;
      const b = MASTER_KEY_CONSUMERS[j]!;
      if (!pairIsDisjoint(a, b)) {
        failures.push(`${a.id} (${a.file}) and ${b.id} (${b.file}) do not have a provably disjoint (salt, info) pair`);
      }
    }
  }
  assert.deepEqual(failures, [], failures.join('\n'));
});

// ── §12.2::12 constraint — a salt that could equal `tenant:{tenantId}` must
// not pair with empty info ──────────────────────────────────────────────────

test('CHARIOT::§12.2::12 — every non-vault consumer whose salt could equal `tenant:{tenantId}` uses non-empty info', () => {
  const vault = MASTER_KEY_CONSUMERS.find((c) => c.id === 'credential-vault');
  assert.ok(vault, 'credential-vault entry must be registered as the tenant:{tenantId} salt owner');

  const failures: string[] = [];
  for (const consumer of MASTER_KEY_CONSUMERS) {
    if (consumer.id === vault!.id) continue; // the vault itself is the admitted exception
    if (saltsCouldCollide(consumer.salt, vault!.salt) && consumer.info.kind === 'empty') {
      failures.push(`${consumer.id} (${consumer.file}) has a salt that could equal tenant:{tenantId} and empty info`);
    }
  }
  assert.deepEqual(failures, [], failures.join('\n'));
});

test('CHARIOT::§12.2::12 — the vault entry is the only registered consumer with empty info', () => {
  const emptyInfoConsumers = MASTER_KEY_CONSUMERS.filter((c) => c.info.kind === 'empty').map((c) => c.id);
  assert.deepEqual(emptyInfoConsumers, ['credential-vault']);
});

// ── Registry-vs-source drift (the manifest cannot silently diverge) ────────

function readSource(relPath: string): string {
  return readFileSync(join(repoRoot, relPath), 'utf-8');
}

test('registry drift: credential-vault salt bytes (`tenant:` prefix format) match native/src/vault.rs', () => {
  const src = readSource('native/src/vault.rs');
  assert.match(
    src,
    /format!\(\s*"tenant:\{\}"\s*,\s*tenant_id\s*\)/,
    'vault.rs must build the salt as format!("tenant:{}", tenant_id) — matches the registry\'s templatePrefix "tenant:"',
  );
});

test('registry drift: credential-vault uses empty HKDF info per the registry', () => {
  const src = readSource('native/src/vault.rs');
  assert.match(src, /hk\.expand\(b""\s*,/, 'vault.rs derive_key must call hk.expand(b"", ...) — empty info, matching the registry');
});

test('registry drift: iam-mfa-totp salt/info literals match src/iam/services/mfa.ts', () => {
  const src = readSource('src/iam/services/mfa.ts');
  const mfa = MASTER_KEY_CONSUMERS.find((c) => c.id === 'iam-mfa-totp')!;
  assert.equal(mfa.salt.kind, 'literal');
  assert.ok(
    src.includes(`'${(mfa.salt as { value: string }).value}'`) || src.includes(`"${(mfa.salt as { value: string }).value}"`),
    `mfa.ts must contain the literal salt ${(mfa.salt as { value: string }).value} claimed by the registry`,
  );
  assert.match(src, /`mfa:\$\{tenantId\}`/, 'mfa.ts info must be the template `mfa:${tenantId}` — matches the registry\'s templatePrefix "mfa:"');
});

test('registry drift: edge-snapshot-seal info literal matches native/src/edge_snapshot.rs', () => {
  const src = readSource('native/src/edge_snapshot.rs');
  const edge = MASTER_KEY_CONSUMERS.find((c) => c.id === 'edge-snapshot-seal')!;
  assert.equal(edge.info.kind, 'literal');
  const infoValue = (edge.info as { value: string }).value;
  assert.ok(
    src.includes(`b"${infoValue}"`),
    `edge_snapshot.rs must contain the literal HKDF info b"${infoValue}" claimed by the registry`,
  );
});

// ── Coverage: every ENTERPRISE_MASTER_KEY-rooted derivation call site is
// registered (CHARIOT::§12.2::11/13) ─────────────────────────────────────────
//
// The finding this section closes: a PURELY SYNTACTIC scan over raw source
// text (the original `HKDF_TOKEN.test(src)` regex against the whole file) is
// evadable — a destructured alias (`const { hkdfSync: h } = crypto; h(...)`),
// an indirect function alias, `subtle.deriveBits`, a renamed/imported Rust
// symbol (`use hkdf::Hkdf as K`), or a token that happens to appear only
// inside a comment/string could either dodge detection or produce a false
// positive. This section:
//   1. strips comments and string/template literals PER LANGUAGE before
//      scanning, so prose can neither trigger nor mask a hit;
//   2. matches a wider, still-evadable-resistant token set: for TS/JS, any
//      BARE IDENTIFIER occurrence of a KDF-family name (aliasing a binding
//      does not remove the original name from the import/destructure site —
//      it must appear there at least once for the alias to exist at all);
//      for Rust, `hkdf` anywhere in a `use` path or type name, or an
//      `.expand(`/`.expand_multi_info(` call;
//   3. classifies EVERY flagged, unregistered file by what secret root it
//      appears to derive from — `ENTERPRISE_MASTER_KEY` explicitly, or
//      "another/unclear root" when no master-key reference is found. Both
//      classifications are a FAILURE when the file is unregistered — an
//      unregistered derivation from an unrecognized root is not silently
//      passed just because it doesn't literally say ENTERPRISE_MASTER_KEY;
//   4. is proven against an evasion corpus below (string fixtures, not
//      files) covering each evasion form named in the gate finding, plus a
//      prose-only fixture proving comments can't cause a false positive.

/**
 * Strip TS/JS `//` and `/* *\/` comments and all string/template literals
 * (single/double/backtick, with backslash-escape awareness), replacing each
 * with a single space so token boundaries are preserved but no comment or
 * string CONTENT can match a token regex. A destructured/aliased binding
 * (`const { hkdfSync: h } = crypto`) still passes through unchanged — only
 * comments and quoted text are removed, never identifiers.
 *
 * Template-literal `${...}` interpolations are RECURSED INTO and scanned as
 * real code (`` `${crypto.hkdfSync(...)}` `` is not opaque) — see
 * `stripTsCore`'s brace-tracking branch below. Only the literal TEXT
 * portions of a template (outside any `${...}`) are stripped as quoted
 * content; a nested template/string/comment inside an interpolation is
 * itself stripped correctly because `stripTsCore` recurses on backticks
 * wherever it runs.
 *
 * Known simplification: does not distinguish a `/` division operator from a
 * regex-literal delimiter. This does not affect the token classes scanned
 * for here (KDF-family identifiers are never regex literals).
 */
function stripTsCommentsAndStrings(src: string): string {
  return stripTsCore(src, 0, false).out;
}

/**
 * Core recursive-descent scanner shared by `stripTsCommentsAndStrings` and
 * its own template-interpolation recursion. `stopAtBraceClose` is true only
 * when this call is scanning the CONTENTS of a `${ ... }` interpolation
 * (invoked right after consuming the `${`): it then tracks `{`/`}` nesting
 * (so an object literal `{ a: 1 }` inside the interpolation doesn't end the
 * scan early) and returns as soon as it sees the `}` that closes the
 * interpolation itself (brace depth back to 0), handing the caller the
 * index just past that `}` so the enclosing template literal can resume.
 */
function stripTsCore(src: string, start: number, stopAtBraceClose: boolean): { out: string; endIndex: number } {
  let out = '';
  let i = start;
  const n = src.length;
  let braceDepth = 0;
  while (i < n) {
    const c = src[i];
    const c2 = i + 1 < n ? src[i + 1] : '';
    if (stopAtBraceClose && c === '{') {
      braceDepth++;
      out += c;
      i++;
      continue;
    }
    if (stopAtBraceClose && c === '}') {
      if (braceDepth === 0) {
        i++; // consume the interpolation's own closing brace
        return { out, endIndex: i };
      }
      braceDepth--;
      out += c;
      i++;
      continue;
    }
    if (c === '/' && c2 === '/') {
      i += 2;
      while (i < n && src[i] !== '\n') i++;
      continue;
    }
    if (c === '/' && c2 === '*') {
      i += 2;
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) i++;
      i += 2;
      continue;
    }
    if (c === '"' || c === "'") {
      const quote = c;
      out += ' ';
      i++;
      while (i < n) {
        if (src[i] === '\\') {
          i += 2;
          continue;
        }
        if (src[i] === quote) {
          i++;
          break;
        }
        i++;
      }
      continue;
    }
    if (c === '`') {
      out += ' ';
      i++;
      while (i < n) {
        if (src[i] === '\\') {
          i += 2;
          continue;
        }
        if (src[i] === '`') {
          i++;
          break;
        }
        if (src[i] === '$' && src[i + 1] === '{') {
          i += 2; // consume `${` — recurse into the interpolation as CODE
          const sub = stripTsCore(src, i, true);
          out += ' ' + sub.out + ' ';
          i = sub.endIndex;
          continue;
        }
        i++;
      }
      continue;
    }
    out += c;
    i++;
  }
  return { out, endIndex: i };
}

/**
 * Strip Rust `//` and `/* *\/` comments (block comments are nesting-aware,
 * per Rust's grammar) and `"..."`/`b"..."`/`r"..."`/`br"..."`/`r#"..."#`
 * string and byte-string literals, replacing each with a single space.
 * Char literals (`'x'`) are intentionally NOT stripped — disambiguating a
 * char literal from a lifetime (`'a`) reliably needs a real lexer, and no
 * token class scanned for here can hide inside a single-character literal.
 * A renamed `use` alias (`use hkdf::Hkdf as K`) still passes through
 * unchanged — only comments and quoted text are removed, never identifiers
 * or `use` paths.
 */
function stripRustCommentsAndStrings(src: string): string {
  let out = '';
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];
    const c2 = i + 1 < n ? src[i + 1] : '';
    if (c === '/' && c2 === '/') {
      i += 2;
      while (i < n && src[i] !== '\n') i++;
      continue;
    }
    if (c === '/' && c2 === '*') {
      i += 2;
      let depth = 1;
      while (i < n && depth > 0) {
        if (src[i] === '/' && src[i + 1] === '*') {
          depth++;
          i += 2;
          continue;
        }
        if (src[i] === '*' && src[i + 1] === '/') {
          depth--;
          i += 2;
          continue;
        }
        i++;
      }
      continue;
    }
    // Raw / byte-raw strings: r"...", r#"..."#, br"...", br#"..."#.
    const rawMatch = /^(br|r)(#*)"/.exec(src.slice(i));
    if (rawMatch) {
      const hashes = rawMatch[2] ?? '';
      const closer = `"${hashes}`;
      i += rawMatch[0].length;
      out += ' ';
      const end = src.indexOf(closer, i);
      i = end === -1 ? n : end + closer.length;
      continue;
    }
    // Plain / byte strings: "...", b"...". Escape-aware.
    if (c === '"' || (c === 'b' && c2 === '"')) {
      i += c === 'b' ? 1 : 0;
      out += ' ';
      i++; // consume the opening quote
      while (i < n) {
        if (src[i] === '\\') {
          i += 2;
          continue;
        }
        if (src[i] === '"') {
          i++;
          break;
        }
        i++;
      }
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

/**
 * Decode every `\uXXXX` and `\u{...}` JS/TS unicode escape in the raw
 * source into its literal character, so an escaped identifier
 * (`crypto.hkdfSync`, indistinguishable from `crypto.hkdfSync` to the
 * TS/JS parser) or an escaped string-literal character normalises to plain
 * text BEFORE any other scanning runs. Applied unconditionally to both code
 * and string/comment text — a false match this could introduce inside a
 * comment/string is caught by comment/string stripping (which runs AFTER
 * this on the DECODED text), so decoding first only ever widens what can be
 * seen, never narrows what strips correctly.
 */
function decodeUnicodeEscapes(src: string): string {
  return src
    .replace(/\\u\{([0-9a-fA-F]+)\}/g, (whole, hex: string) => {
      try {
        return String.fromCodePoint(parseInt(hex, 16));
      } catch {
        return whole;
      }
    })
    .replace(/\\u([0-9a-fA-F]{4})/g, (whole, hex: string) => {
      try {
        return String.fromCharCode(parseInt(hex, 16));
      } catch {
        return whole;
      }
    });
}

/** TS/JS KDF-family bare-identifier tokens. Matched on STRIPPED source, so a
 * hit can only come from real code — never a comment or a string. Because
 * aliasing (`const { hkdfSync: h } = crypto`, `const derive = crypto.hkdfSync`)
 * requires the ORIGINAL name to appear at the binding site, every alias form
 * in the gate finding still matches one of these identifiers at least once. */
const TS_KDF_IDENTIFIER = /\b(hkdf|hkdfSync|deriveBits|deriveKey|pbkdf2|pbkdf2Sync|scrypt|scryptSync)\b/i;

/** A `node:crypto`/`crypto` import or require that binds one of the
 * subtle/webcrypto surfaces `deriveBits` can be reached through, even when
 * the binding is itself renamed. Matched on STRIPPED source for the
 * identifier list, but the import/require KEYWORD context is checked on the
 * unstripped source since the module specifier is itself a string literal
 * (stripped source no longer carries `'node:crypto'`, only the imported
 * names, which is exactly what this needs). */
const CRYPTO_MODULE_IMPORT = /\b(?:import|require)\b[\s\S]{0,200}?['"](?:node:)?crypto['"]/;
const CRYPTO_SUBTLE_BINDING = /\b(subtle|webcrypto)\b/i;

/**
 * Computed-property-access evasion: `crypto['hkdfSync'](...)`,
 * `c["deriveBits"]`. `TS_KDF_IDENTIFIER` alone misses these because the
 * identifier is INSIDE a string/template literal, and string/template
 * literal CONTENT is exactly what `stripTsCommentsAndStrings` removes
 * before the identifier regex ever runs.
 *
 * Extracts the CONTENT of every string/template literal that is adjacent
 * to `[ ... ]` bracket-member access or passed to `require(`/`import(` —
 * checked on RAW (unstripped) source, since the bracket/call syntax
 * context is exactly what stripping destroys — and tests that content
 * against `TS_KDF_IDENTIFIER`. The adjacency requirement is what keeps a
 * plain prose sentence that happens to spell "hkdfSync" (the existing
 * string-literal-only negative control) from being flagged: a string with
 * no bracket/call adjacency never matches either pattern below, so it
 * never reaches the identifier test at all.
 *
 * Whitespace-tolerant on both sides (`crypto [ 'hkdfSync' ] ( ... )`,
 * `require( 'x' )`), matching the tolerance applied to the Rust call
 * patterns below — a cosmetic reformatting is not a hiding place either.
 */
const BRACKET_ACCESS_LITERAL = /\[\s*['"`]([^'"`]*)['"`]\s*\]/g;
const REQUIRE_IMPORT_LITERAL = /\b(?:require|import)\s*\(\s*['"`]([^'"`]*)['"`]\s*\)/g;

function hasComputedKdfAccess(rawSrc: string): boolean {
  for (const re of [BRACKET_ACCESS_LITERAL, REQUIRE_IMPORT_LITERAL]) {
    re.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = re.exec(rawSrc)) !== null) {
      const literalContent = match[1] ?? '';
      if (TS_KDF_IDENTIFIER.test(literalContent)) return true;
    }
  }
  return false;
}

/**
 * Rust KDF-family tokens: `hkdf` anywhere (a `use` path, a type mention, or
 * a renamed `as` alias — the literal crate/type name `hkdf`/`Hkdf` must
 * still appear for the alias to exist), or an `.expand(` / `.expand_multi_
 * info(` / `extract(` call, all of which appear only on an Hkdf value in
 * this codebase's dependency set. Whitespace-tolerant between the method
 * name and its opening paren (`.expand (`, `.expand_multi_info  (`,
 * `extract (`) — reformatting is not an evasion. Case-insensitive: Rust
 * identifiers are case-sensitive to the compiler, but this scanner
 * intentionally matches `HKDF`/`Hkdf`/`hkdf` alike so a stylistic rename
 * can't dodge it either.
 */
const RUST_KDF_TOKEN = /\bhkdf\b|\.\s*expand\s*\(|\.\s*expand_multi_info\s*\(|\bextract\s*\(/i;

/** True iff the TS/JS source (given RAW, i.e. not yet stripped or
 * unicode-decoded) contains a KDF-family call site by any of the
 * evasion-resistant token classes. Decodes `\uXXXX`/`\u{...}` escapes
 * first (an escaped identifier is indistinguishable from the plain one to
 * the real parser). */
function hasTsDerivationCallSite(rawSrcInput: string): boolean {
  const rawSrc = decodeUnicodeEscapes(rawSrcInput);
  const stripped = stripTsCommentsAndStrings(rawSrc);
  if (TS_KDF_IDENTIFIER.test(stripped)) return true;
  if (CRYPTO_MODULE_IMPORT.test(rawSrc) && CRYPTO_SUBTLE_BINDING.test(stripped)) return true;
  if (hasComputedKdfAccess(rawSrc)) return true;
  return false;
}

/** True iff the Rust source (given RAW) contains a KDF-family call site. */
function hasRustDerivationCallSite(rawSrcInput: string): boolean {
  const rawSrc = decodeUnicodeEscapes(rawSrcInput);
  const stripped = stripRustCommentsAndStrings(rawSrc);
  return RUST_KDF_TOKEN.test(stripped);
}

/**
 * Master-key MATERIAL reference — the exact five-name set named in the
 * structural-rule gate finding. Used both to classify an already-flagged
 * (identifier-based) hit's apparent root, AND as half of the STRUCTURAL
 * candidate rule below (the other half is "references a crypto
 * capability"). Checked on the RAW (decoded) source — these are always
 * real identifiers/env-var names in this codebase's actual call sites,
 * never comment-only or string-only text, so raw-source matching only
 * ever WIDENS what gets examined, never narrows a scan that already ran on
 * stripped source.
 */
const MASTER_KEY_MATERIAL_TS = /\b(?:ENTERPRISE_MASTER_KEY|getMasterKeyB64|masterKeyB64|master_key|masterKey)\b/;

function classifyRoot(rawSrc: string): 'ENTERPRISE_MASTER_KEY' | 'another/unclear root' {
  return MASTER_KEY_MATERIAL_TS.test(rawSrc) ? 'ENTERPRISE_MASTER_KEY' : 'another/unclear root';
}

// ── Structural candidate rule (CHARIOT::§12.2::11, does not depend on
// naming a KDF) ─────────────────────────────────────────────────────────
//
// The identifier-based detectors above (hasTsDerivationCallSite /
// hasRustDerivationCallSite) are fundamentally syntactic: they cannot be
// complete, because a sufficiently indirect JS/TS program can obtain and
// call ANY function without ever writing its name as source text next to
// the object it lives on — `const k = 'hkdf' + 'Sync'; crypto[k](...)`,
// `Reflect.get(crypto, 'hkdfSync')(...)`. This rule does not try to name
// the KDF at all: a file is a STRUCTURAL candidate when it references
// master-key material (`MASTER_KEY_MATERIAL_TS` above) AND references ANY
// crypto capability — regardless of what it does with that capability. A
// candidate must be registered, a documented delegator, or a verified
// test-fixture deriver; otherwise the coverage test fails, naming the
// matched signals. A file can be flagged by EITHER this rule or the
// identifier-based detectors — this is a SECOND, independent detector, not
// a replacement.

/** Extracts every `from '...'`/`require('...')`/`import('...')` module
 * specifier and returns the first one that names a crypto-shaped package:
 * exactly `crypto`/`node:crypto`, any `@noble/*` scope, `hash-wasm`, or any
 * specifier whose name contains (case-insensitively) `crypto`, `hkdf`,
 * `kdf`, `pbkdf`, `scrypt`, or `argon`. Checked on RAW source (the
 * specifier is itself a string literal). */
const IMPORT_SPECIFIER = /\b(?:from|require|import)\s*\(?\s*['"`]([^'"`]+)['"`]/g;
const CRYPTO_SHAPED_PACKAGE_NAME = /crypto|hkdf|kdf|pbkdf|scrypt|argon/i;

function findCryptoShapedImport(rawSrc: string): string | null {
  IMPORT_SPECIFIER.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = IMPORT_SPECIFIER.exec(rawSrc)) !== null) {
    const spec = match[1] ?? '';
    if (spec === 'crypto' || spec === 'node:crypto') return spec;
    if (spec.startsWith('@noble/')) return spec;
    if (spec === 'hash-wasm') return spec;
    if (CRYPTO_SHAPED_PACKAGE_NAME.test(spec)) return spec;
  }
  return null;
}

const BARE_CRYPTO_IDENTIFIER = /\b(crypto|webcrypto|subtle)\b/;
// "globalThis ... crypto" — the Node global needs no import at all.
const GLOBALTHIS_CRYPTO = /\bglobalThis\b[\s\S]{0,200}?\bcrypto\b/;
const REFLECT_GET_APPLY = /\bReflect\s*\.\s*(?:get|apply)\s*\(/;

export interface StructuralTsResult {
  readonly masterKeyMaterial: boolean;
  readonly cryptoCapability: boolean;
  readonly signals: readonly string[];
}

/**
 * Evaluate the structural rule for one TS/JS file. Decodes unicode escapes
 * first (same reason as the identifier-based detectors). `cryptoCapability`
 * signals are checked on STRIPPED source for the bare-identifier and
 * `globalThis` sub-checks (so a doc comment mentioning "the crypto module"
 * in prose doesn't trip them), but on RAW source for the import-specifier
 * and `Reflect` sub-checks (an import specifier is itself a string
 * literal, and `Reflect.get(` is unambiguous code syntax not typically
 * written in prose).
 */
function structuralTsSignals(rawSrcInput: string): StructuralTsResult {
  const rawSrc = decodeUnicodeEscapes(rawSrcInput);
  const stripped = stripTsCommentsAndStrings(rawSrc);
  const masterKeyMaterial = MASTER_KEY_MATERIAL_TS.test(rawSrc);
  const signals: string[] = [];
  const imp = findCryptoShapedImport(rawSrc);
  if (imp) signals.push(`import:${imp}`);
  if (BARE_CRYPTO_IDENTIFIER.test(stripped)) signals.push('bare-identifier:crypto/webcrypto/subtle');
  if (GLOBALTHIS_CRYPTO.test(stripped)) signals.push('globalThis..crypto');
  if (masterKeyMaterial && REFLECT_GET_APPLY.test(stripped)) signals.push('Reflect.get/apply');
  return { masterKeyMaterial, cryptoCapability: signals.length > 0, signals };
}

const RUST_CRATE_USE = /\buse\s+(?:\w+::)*(hkdf|ring|sha2|hmac|pbkdf2|scrypt|argon2|aes_gcm)\b/i;

export interface StructuralRustResult {
  readonly masterKeyMaterial: boolean;
  readonly cryptoCapability: boolean;
  readonly signals: readonly string[];
}

function structuralRustSignals(rawSrcInput: string): StructuralRustResult {
  const rawSrc = decodeUnicodeEscapes(rawSrcInput);
  const masterKeyMaterial = MASTER_KEY_MATERIAL_TS.test(rawSrc); // ENTERPRISE_MASTER_KEY / master_key are shared across languages
  const signals: string[] = [];
  const useMatch = RUST_CRATE_USE.exec(rawSrc);
  if (useMatch) signals.push(`use:${(useMatch[1] ?? '').toLowerCase()}`);
  return { masterKeyMaterial, cryptoCapability: signals.length > 0, signals };
}

const REGISTERED_FILES = new Set(MASTER_KEY_CONSUMERS.map((c) => c.file));

// This registry module itself documents (in prose/comments) the salt/info
// literals and the word "HKDF" for every consumer above, which would
// otherwise trip the coverage scan below on its own doc comments even after
// comment-stripping IF it ever named a bare `hkdf`/`hkdfSync` identifier in
// actual code (it does not — it only holds string literals and prose). It
// performs no HKDF derivation itself, so it is exempt by construction — not
// because it is a registered/delegated call site.
const SELF_EXEMPT_FILES = new Set<string>(['src/iam/masterKeyConsumers.ts', 'src/iam/masterKeyConsumers.test.ts']);

// Delegators: call an already-registered consumer's derivation function with
// their own identifier rather than defining a new (salt, info) formula. See
// the trailing comment block in masterKeyConsumers.ts for the justification
// for each. Adding a file here without that justification is itself a
// registry-drift bug this test cannot catch mechanically — the comment
// block is the audit trail.
// DOCUMENTED_DELEGATORS_LIST (masterKeyConsumers.ts) carries the callee for
// each delegator — used here only as a membership set; see that file for
// the named callee behind each entry.
const DOCUMENTED_DELEGATORS = new Set<string>(DOCUMENTED_DELEGATORS_LIST.map((d) => d.file));

// ── Test-fixture derivations (CHARIOT::§12.2::11 follow-on) ────────────────
//
// TEST_FIXTURE_DERIVERS (masterKeyConsumers.ts) names files whose raw HKDF
// call site builds a pre-CH-10 legacy ciphertext FIXTURE, not a live
// consumer. Being on that list is NOT taken on faith — a listed file is
// accounted for ONLY IF it verifiably (a) has a `.test.ts` path, (b) is
// imported by NO non-test source file anywhere in the repo, and (c)
// contains the `TEST_FIXTURE_MARKER` comment verbatim. A listed file
// failing any of the three is still flagged as unregistered, with the
// specific missing condition(s) named — this is what keeps a real
// derivation helper from hiding behind a `.test.ts` filename and a listing
// in TEST_FIXTURE_DERIVERS while actually being imported by production
// code (the evasion corpus below proves each of the three checks fires
// independently).

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * True iff some NON-TEST `.ts` file under `src/` (a file whose own path
 * does not end `.test.ts`) contains an `import`/`require` specifier whose
 * final path segment is `basename` (with or without a trailing `.js` —
 * the compiled-import extension) or `basename` with its `.test.ts`
 * suffix replaced by `.test.js`. `basenameNoExt` is the file's basename
 * with the `.ts` extension stripped (e.g.
 * `credential-loader.concurrent-upgrade.test`).
 */
function isImportedByNonTestFile(basenameNoExt: string, allFiles: readonly string[], repoRootPath: string): boolean {
  const specifierRe = new RegExp(
    `['"][^'"]*${escapeRegExp(basenameNoExt)}(\\.js)?['"]`,
  );
  for (const absPath of allFiles) {
    const relPath = absPath.slice(repoRootPath.length + 1).split('\\').join('/');
    if (relPath.endsWith('.test.ts')) continue; // only non-test importers count
    if (extname(relPath) !== '.ts') continue;
    const src = readFileSync(absPath, 'utf-8');
    if (specifierRe.test(src)) return true;
  }
  return false;
}

interface FixtureAccountingResult {
  ok: boolean;
  reasons: string[];
}

/**
 * Evaluate the three TEST_FIXTURE_DERIVERS conditions for one file. Pure
 * function (no filesystem access) so the evasion corpus can drive it
 * directly with fabricated inputs — see the tests below.
 */
function checkTestFixtureDeriver(relPath: string, rawSrc: string, importedByNonTest: boolean): FixtureAccountingResult {
  const reasons: string[] = [];
  if (!relPath.endsWith('.test.ts')) reasons.push('path does not end with .test.ts');
  if (importedByNonTest) reasons.push('is imported by a non-test source file');
  if (!rawSrc.includes(TEST_FIXTURE_MARKER)) reasons.push(`missing the marker comment "${TEST_FIXTURE_MARKER}"`);
  return { ok: reasons.length === 0, reasons };
}

const TEST_FIXTURE_DERIVER_FILES = new Set(TEST_FIXTURE_DERIVERS.map((d) => d.file));

// ── Validation-only master-key references (structural-rule follow-on) ─────
//
// VALIDATION_ONLY_FILES (masterKeyConsumers.ts) names files that reference
// master-key material and SOME crypto capability signal (usually only a
// type-level import, or an unrelated crypto usage) but never call a
// derivation/delegator function. Verified negatively: the listed file must
// carry the marker AND must NOT contain a call to any function this
// registry already knows performs real encryption/decryption — if it does,
// the listing is stale (the file should be a DOCUMENTED_DELEGATORS entry
// instead) and the coverage test fails, naming the file.
const KNOWN_DERIVATION_OR_DELEGATOR_CALL =
  /\b(?:encryptFields|decryptFields|decryptFieldsForVaultMigration|sealSigningKey|encryptCredential|decryptCredential)\s*\(/;

function checkValidationOnlyFile(rawSrc: string): FixtureAccountingResult {
  const reasons: string[] = [];
  if (!rawSrc.includes(VALIDATION_ONLY_MARKER)) reasons.push(`missing the marker comment "${VALIDATION_ONLY_MARKER}"`);
  if (KNOWN_DERIVATION_OR_DELEGATOR_CALL.test(rawSrc)) {
    reasons.push('calls a known derivation/delegator function — this is a delegator, not validation-only; move it to DOCUMENTED_DELEGATORS with the callee named');
  }
  return { ok: reasons.length === 0, reasons };
}

const VALIDATION_ONLY_FILE_SET = new Set(VALIDATION_ONLY_FILES.map((f) => f.file));

// ── Transitive delegator-chain verification (CHARIOT::§12.2::11 follow-on) ─
//
// A DOCUMENTED_DELEGATORS entry names its callee, but that alone doesn't
// prove the callee is real accountability rather than a fabricated dead
// end — `calleeFiles` must resolve, transitively, to a registered consumer
// or a validation-only file. `resolveDelegatorChain` walks it, detecting a
// cycle (a delegator whose callee chain revisits a file already on the
// current path) and a dead end (a callee that is none of: registered,
// another delegator, validation-only).

const DOCUMENTED_DELEGATOR_BY_FILE = new Map(DOCUMENTED_DELEGATORS_LIST.map((d) => [d.file, d]));

interface ChainResolution {
  ok: boolean;
  /** The chain of files walked, starting with the delegator itself. */
  chain: string[];
  /** Present iff !ok — 'cycle' or 'dead-end', naming where it broke. */
  failure?: { kind: 'cycle' | 'dead-end'; atFile: string };
}

/**
 * All three lookups are PARAMETERIZED (defaulting to the real registry
 * state) so the evasion corpus below can drive both functions against a
 * synthetic delegator map — proving the mechanism itself, not just its
 * result against the current (already-clean) real registry.
 */
function resolveDelegatorChain(
  startFile: string,
  delegatorMap: ReadonlyMap<string, DocumentedDelegator> = DOCUMENTED_DELEGATOR_BY_FILE,
  registeredFiles: ReadonlySet<string> = REGISTERED_FILES,
  validationOnlyFiles: ReadonlySet<string> = VALIDATION_ONLY_FILE_SET,
): ChainResolution {
  const chain: string[] = [startFile];
  const onPath = new Set<string>([startFile]);
  let current = startFile;

  // The starting file itself must be a documented delegator (that's what
  // we're resolving); everything after the first hop may be a registered
  // consumer, validation-only, or another delegator to recurse into.
  for (;;) {
    const delegator = delegatorMap.get(current);
    if (!delegator) {
      // `current` is not itself a delegator — it must terminate the chain.
      if (registeredFiles.has(current) || validationOnlyFiles.has(current)) {
        return { ok: true, chain };
      }
      return { ok: false, chain, failure: { kind: 'dead-end', atFile: current } };
    }
    // `current` is a delegator: every one of its calleeFiles must itself
    // resolve. A delegator with zero calleeFiles is itself a dead end.
    if (delegator.calleeFiles.length === 0) {
      return { ok: false, chain, failure: { kind: 'dead-end', atFile: current } };
    }
    // Follow the FIRST calleeFile for the reported chain (a delegator with
    // multiple calleeFiles must have EVERY one resolve — checked below,
    // outside this single-path walk — but the chain reported on failure
    // follows the first for readability).
    const next = delegator.calleeFiles[0]!;
    if (onPath.has(next)) {
      return { ok: false, chain: [...chain, next], failure: { kind: 'cycle', atFile: next } };
    }
    chain.push(next);
    onPath.add(next);
    current = next;
  }
}

/** True iff EVERY calleeFile of EVERY delegator on the (first-callee) chain
 * from `startFile` itself resolves (registered, validation-only, or a
 * delegator whose own calleeFiles all resolve) — not just the first. */
function allCalleeFilesResolve(
  file: string,
  seen: Set<string>,
  delegatorMap: ReadonlyMap<string, DocumentedDelegator> = DOCUMENTED_DELEGATOR_BY_FILE,
  registeredFiles: ReadonlySet<string> = REGISTERED_FILES,
  validationOnlyFiles: ReadonlySet<string> = VALIDATION_ONLY_FILE_SET,
): { ok: boolean; deadEndOrCycle?: { kind: 'cycle' | 'dead-end'; atFile: string } } {
  if (seen.has(file)) return { ok: false, deadEndOrCycle: { kind: 'cycle', atFile: file } };
  const delegator = delegatorMap.get(file);
  if (!delegator) {
    if (registeredFiles.has(file) || validationOnlyFiles.has(file)) return { ok: true };
    return { ok: false, deadEndOrCycle: { kind: 'dead-end', atFile: file } };
  }
  if (delegator.calleeFiles.length === 0) return { ok: false, deadEndOrCycle: { kind: 'dead-end', atFile: file } };
  const nextSeen = new Set(seen);
  nextSeen.add(file);
  for (const callee of delegator.calleeFiles) {
    const r = allCalleeFilesResolve(callee, nextSeen, delegatorMap, registeredFiles, validationOnlyFiles);
    if (!r.ok) return r;
  }
  return { ok: true };
}

function listSourceFiles(dir: string, out: string[]): void {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }
  for (const entry of entries) {
    if (entry === 'node_modules' || entry === 'dist' || entry.startsWith('.')) continue;
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      listSourceFiles(full, out);
    } else if (extname(entry) === '.ts' || extname(entry) === '.rs') {
      out.push(full);
    }
  }
}

test('coverage: every candidate (identifier-based OR structural) is registered, a documented delegator, a verified test fixture, or a verified validation-only reference', () => {
  const files: string[] = [];
  listSourceFiles(join(repoRoot, 'src'), files);
  listSourceFiles(join(repoRoot, 'native', 'src'), files);

  const flagged: Array<{ file: string; root: string; reasons: string[] }> = [];
  for (const absPath of files) {
    const relPath = absPath.slice(repoRoot.length + 1).split('\\').join('/');
    if (REGISTERED_FILES.has(relPath) || DOCUMENTED_DELEGATORS.has(relPath) || SELF_EXEMPT_FILES.has(relPath)) continue;

    const rawSrc = readFileSync(absPath, 'utf-8');
    const isRust = extname(relPath) === '.rs';

    // Detector 1: identifier-based (comment/string-stripped, alias-resistant).
    const identifierHit = isRust ? hasRustDerivationCallSite(rawSrc) : hasTsDerivationCallSite(rawSrc);
    // Detector 2: structural — does not depend on naming a KDF at all.
    const structural = isRust ? structuralRustSignals(rawSrc) : structuralTsSignals(rawSrc);
    const structuralDerivationCandidate = structural.masterKeyMaterial && structural.cryptoCapability;
    // Master-key material with NO crypto capability referenced: not a
    // derivation candidate, but must still be accounted for — "reported as
    // delegator-candidate, not silently passed."
    const structuralDelegatorCandidateOnly = structural.masterKeyMaterial && !structural.cryptoCapability && !identifierHit && !structuralDerivationCandidate;

    const isCandidate = identifierHit || structuralDerivationCandidate || structuralDelegatorCandidateOnly;
    if (!isCandidate) continue;

    if (TEST_FIXTURE_DERIVER_FILES.has(relPath)) {
      // Verify, never trust: a TEST_FIXTURE_DERIVERS listing alone does
      // NOT account for the file — all three conditions must hold.
      const basenameNoExt = relPath.slice(relPath.lastIndexOf('/') + 1).replace(/\.ts$/, '');
      const importedByNonTest = isImportedByNonTestFile(basenameNoExt, files, repoRoot);
      const verdict = checkTestFixtureDeriver(relPath, rawSrc, importedByNonTest);
      if (verdict.ok) continue; // accounted for — not flagged
      flagged.push({ file: relPath, root: classifyRoot(rawSrc), reasons: verdict.reasons });
      continue;
    }

    if (VALIDATION_ONLY_FILE_SET.has(relPath)) {
      const verdict = checkValidationOnlyFile(rawSrc);
      if (verdict.ok) continue; // accounted for — not flagged
      flagged.push({ file: relPath, root: classifyRoot(rawSrc), reasons: verdict.reasons });
      continue;
    }

    // Not accounted for anywhere — classify and report the matched signals.
    // A failure REGARDLESS of what root/classification it is — an
    // unregistered candidate (of ANY class, including a bare
    // delegator-candidate with no crypto capability) is not silently
    // passed, per the gate finding.
    const classification = identifierHit
      ? 'derivation-candidate (identifier-based)'
      : structuralDerivationCandidate
        ? 'derivation-candidate (structural)'
        : 'delegator-candidate (master-key material referenced, no crypto capability signal)';
    const signalsNote = structural.signals.length > 0 ? `signals: ${structural.signals.join(', ')}` : 'signals: (none — identifier-based hit only)';
    flagged.push({ file: relPath, root: classifyRoot(rawSrc), reasons: [`${classification}; ${signalsNote}`] });
  }

  assert.deepEqual(
    flagged,
    [],
    flagged.length === 0
      ? ''
      : `unaccounted candidate(s) — add to MASTER_KEY_CONSUMERS, DOCUMENTED_DELEGATORS (naming the callee), TEST_FIXTURE_DERIVERS, or VALIDATION_ONLY_FILES (fixing any listed condition):\n${flagged
          .map((f) => `  - ${f.file} (root: ${f.root}) — ${f.reasons.join('; ')}`)
          .join('\n')}`,
  );
});

test('TEST_FIXTURE_DERIVERS drift: every listed file exists, has a derivation call site, and is currently accounted for', () => {
  const files: string[] = [];
  listSourceFiles(join(repoRoot, 'src'), files);
  listSourceFiles(join(repoRoot, 'native', 'src'), files);

  const failures: string[] = [];
  for (const { file, reason } of TEST_FIXTURE_DERIVERS) {
    if (!reason || reason.trim().length === 0) {
      failures.push(`${file}: TEST_FIXTURE_DERIVERS entry has no reason`);
      continue;
    }
    const absPath = join(repoRoot, file);
    let rawSrc: string;
    try {
      rawSrc = readFileSync(absPath, 'utf-8');
    } catch {
      failures.push(`${file}: listed in TEST_FIXTURE_DERIVERS but does not exist on disk`);
      continue;
    }
    if (!hasTsDerivationCallSite(rawSrc)) {
      failures.push(`${file}: listed in TEST_FIXTURE_DERIVERS but the scanner no longer detects a derivation call site in it — entry is stale, remove it`);
      continue;
    }
    const basenameNoExt = file.slice(file.lastIndexOf('/') + 1).replace(/\.ts$/, '');
    const importedByNonTest = isImportedByNonTestFile(basenameNoExt, files, repoRoot);
    const verdict = checkTestFixtureDeriver(file, rawSrc, importedByNonTest);
    if (!verdict.ok) {
      failures.push(`${file}: ${verdict.reasons.join('; ')}`);
    }
  }
  assert.deepEqual(failures, [], failures.join('\n'));
});

test('DOCUMENTED_DELEGATORS chain: every entry names a calleeFiles chain that terminates in a registered consumer or a validation-only file', () => {
  const failures: string[] = [];
  for (const delegator of DOCUMENTED_DELEGATORS_LIST) {
    if (delegator.calleeFiles.length === 0) {
      failures.push(`${delegator.file}: calleeFiles is empty — a DOCUMENTED_DELEGATORS entry must name at least one callee file`);
      continue;
    }
    const result = allCalleeFilesResolve(delegator.file, new Set());
    if (!result.ok) {
      const readableChain = resolveDelegatorChain(delegator.file);
      const failure = result.deadEndOrCycle!;
      failures.push(
        `${delegator.file}: ${failure.kind} at "${failure.atFile}" — chain: ${readableChain.chain.join(' -> ')}`,
      );
    }
  }
  assert.deepEqual(failures, [], failures.join('\n'));
});

// ── Dynamic loader sites (CHARIOT::§12.2::11, MASTER ruling accept-all) ────
//
// DYNAMIC_LOADER_SITES (masterKeyConsumers.ts) names the five call sites
// exempted from `local/no-dynamic-module-specifier` — never trusted, always
// verified: (a) each listed file carries EXACTLY ONE disable directive for
// that rule, and it carries the `DYNAMIC_LOADER_SITES:` marker (never a
// bare, unexplained disable); (b) repo-wide, NO disable directive for
// `local/no-dynamic-module-specifier` OR `local/no-dynamic-crypto-access`
// exists anywhere under `src/` outside this exact accounted-for set — an
// unlisted directive for EITHER rule fails the test naming the file:line,
// so a future disable comment can never land silently.

const DYNAMIC_LOADER_MARKER = 'DYNAMIC_LOADER_SITES:';
// Matches an eslint-disable comment (any of the three forms) naming the
// given rule anywhere on the same comment line — deliberately permissive
// about the disable KEYWORD form (-next-line / -line / bare block) since
// what matters is that the rule name and (for the accounted-for set) the
// marker both appear together on one directive line.
function disableDirectiveRegexFor(ruleName: string): RegExp {
  return new RegExp(`eslint-disable(?:-next-line|-line)?[^\\n]*\\b${ruleName.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')}\\b`, 'g');
}
const MODULE_SPECIFIER_DISABLE_RE = disableDirectiveRegexFor('local/no-dynamic-module-specifier');
const CRYPTO_ACCESS_DISABLE_RE = disableDirectiveRegexFor('local/no-dynamic-crypto-access');

test('DYNAMIC_LOADER_SITES: every listed file has exactly one no-dynamic-module-specifier disable directive carrying the marker', () => {
  const failures: string[] = [];
  for (const site of DYNAMIC_LOADER_SITES) {
    const absPath = join(repoRoot, site.file);
    let rawSrc: string;
    try {
      rawSrc = readFileSync(absPath, 'utf-8');
    } catch {
      failures.push(`${site.file}: listed in DYNAMIC_LOADER_SITES but does not exist on disk`);
      continue;
    }
    const lines = rawSrc.split('\n');
    const directiveLines = lines
      .map((line, i) => ({ line, lineNo: i + 1 }))
      .filter(({ line }) => {
        MODULE_SPECIFIER_DISABLE_RE.lastIndex = 0;
        return MODULE_SPECIFIER_DISABLE_RE.test(line);
      });
    if (directiveLines.length === 0) {
      failures.push(`${site.file}: no local/no-dynamic-module-specifier disable directive found`);
      continue;
    }
    if (directiveLines.length > 1) {
      failures.push(`${site.file}: expected exactly one disable directive, found ${directiveLines.length} at lines ${directiveLines.map((d) => d.lineNo).join(', ')}`);
      continue;
    }
    const [{ line, lineNo }] = directiveLines;
    if (!line!.includes(DYNAMIC_LOADER_MARKER)) {
      failures.push(`${site.file}:${lineNo}: disable directive is missing the "${DYNAMIC_LOADER_MARKER}" marker — a bare/unexplained disable is forbidden`);
    }
    if (!site.reason || site.reason.trim().length === 0) {
      failures.push(`${site.file}: DYNAMIC_LOADER_SITES entry has no reason`);
    }
  }
  assert.deepEqual(failures, [], failures.join('\n'));
});

test('DYNAMIC_LOADER_SITES: no OTHER disable directive for either local rule exists anywhere under src/', () => {
  const files: string[] = [];
  listSourceFiles(join(repoRoot, 'src'), files);
  const accountedForFiles = new Set(DYNAMIC_LOADER_SITES.map((s) => s.file));

  const unaccountedFor: string[] = [];
  for (const absPath of files) {
    if (extname(absPath) !== '.ts') continue;
    const relPath = absPath.slice(repoRoot.length + 1).split('\\').join('/');
    const rawSrc = readFileSync(absPath, 'utf-8');
    const lines = rawSrc.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;
      MODULE_SPECIFIER_DISABLE_RE.lastIndex = 0;
      CRYPTO_ACCESS_DISABLE_RE.lastIndex = 0;
      const hasModuleSpecifierDisable = MODULE_SPECIFIER_DISABLE_RE.test(line);
      const hasCryptoAccessDisable = CRYPTO_ACCESS_DISABLE_RE.test(line);
      if (!hasModuleSpecifierDisable && !hasCryptoAccessDisable) continue;
      if (hasCryptoAccessDisable) {
        // local/no-dynamic-crypto-access has ZERO accounted-for exemptions
        // — any disable of it anywhere is unaccounted for by definition.
        unaccountedFor.push(`${relPath}:${i + 1}: disables local/no-dynamic-crypto-access (no exemption for this rule exists)`);
        continue;
      }
      // hasModuleSpecifierDisable: only OK if this file is in
      // DYNAMIC_LOADER_SITES (the per-file directive-count/marker check
      // above already verified it's well-formed there).
      if (!accountedForFiles.has(relPath)) {
        unaccountedFor.push(`${relPath}:${i + 1}: disables local/no-dynamic-module-specifier but is not listed in DYNAMIC_LOADER_SITES`);
      }
    }
  }
  assert.deepEqual(unaccountedFor, [], unaccountedFor.join('\n'));
});

// ── Evasion corpus: transitive delegator chain (synthetic maps — no real
// registry entries touched) — "the gate's helper is the callee of a
// master-key-holding caller" ────────────────────────────────────────────

test('evasion corpus: a delegator naming an unregistered/undocumented helper as callee is a dead end', () => {
  // 'src/example/caller.ts' claims to delegate to 'src/example/helper.ts',
  // but helper.ts is neither registered, another delegator, nor
  // validation-only — exactly the gate's "helper is the callee of a
  // master-key-holding caller" shape, where the helper itself was never
  // accounted for.
  const syntheticDelegators = new Map<string, DocumentedDelegator>([
    [
      'src/example/caller.ts',
      { file: 'src/example/caller.ts', callee: 'src/example/helper.ts doTheRealWork', calleeFiles: ['src/example/helper.ts'] },
    ],
  ]);
  const result = allCalleeFilesResolve('src/example/caller.ts', new Set(), syntheticDelegators, REGISTERED_FILES, VALIDATION_ONLY_FILE_SET);
  assert.equal(result.ok, false, 'a delegator whose callee is unaccounted for must fail, not silently pass');
  assert.deepEqual(result.deadEndOrCycle, { kind: 'dead-end', atFile: 'src/example/helper.ts' });

  const readable = resolveDelegatorChain('src/example/caller.ts', syntheticDelegators, REGISTERED_FILES, VALIDATION_ONLY_FILE_SET);
  assert.equal(readable.ok, false);
  assert.deepEqual(readable.chain, ['src/example/caller.ts', 'src/example/helper.ts']);
});

test('evasion corpus: the SAME caller/helper pair resolves once the helper is registered', () => {
  const syntheticDelegators = new Map<string, DocumentedDelegator>([
    [
      'src/example/caller.ts',
      { file: 'src/example/caller.ts', callee: 'src/example/helper.ts doTheRealWork', calleeFiles: ['src/example/helper.ts'] },
    ],
  ]);
  // Now the helper is registered as a real consumer (or, in this
  // alternative, listed as validation-only) — the SAME chain resolves.
  const registeredWithHelper = new Set([...REGISTERED_FILES, 'src/example/helper.ts']);
  const result = allCalleeFilesResolve('src/example/caller.ts', new Set(), syntheticDelegators, registeredWithHelper, VALIDATION_ONLY_FILE_SET);
  assert.equal(result.ok, true, 'once the helper is registered, the caller\'s chain must resolve');
});

test('evasion corpus: a cyclic delegator chain (A -> B -> A) is caught, not infinitely looped or silently passed', () => {
  const syntheticDelegators = new Map<string, DocumentedDelegator>([
    ['src/example/a.ts', { file: 'src/example/a.ts', callee: 'b', calleeFiles: ['src/example/b.ts'] }],
    ['src/example/b.ts', { file: 'src/example/b.ts', callee: 'a', calleeFiles: ['src/example/a.ts'] }],
  ]);
  const result = allCalleeFilesResolve('src/example/a.ts', new Set(), syntheticDelegators, REGISTERED_FILES, VALIDATION_ONLY_FILE_SET);
  assert.equal(result.ok, false, 'a cyclic delegator chain must fail, not silently pass or loop forever');
  assert.equal(result.deadEndOrCycle?.kind, 'cycle');
});

// ── Evasion corpus: TEST_FIXTURE_DERIVERS accounting (checkTestFixtureDeriver
// is a pure function, driven directly with fabricated inputs — no real
// files touched) ────────────────────────────────────────────────────────────

test('evasion corpus: a TEST_FIXTURE_DERIVERS-listed file WITHOUT the marker comment is still flagged', () => {
  const src = `
    import { hkdfSync } from 'node:crypto';
    function legacyFixture() { return hkdfSync('sha256', Buffer.alloc(32), Buffer.from('tenant:x'), Buffer.alloc(0), 32); }
  `;
  const verdict = checkTestFixtureDeriver('src/iam/some-fixture.test.ts', src, false);
  assert.equal(verdict.ok, false, 'a listed file missing the marker comment must not be accounted for');
  assert.ok(
    verdict.reasons.some((r) => r.includes('marker comment')),
    `expected a "missing marker comment" reason, got: ${verdict.reasons.join('; ')}`,
  );
});

test('evasion corpus: a TEST_FIXTURE_DERIVERS-listed file imported by a non-test source file is still flagged, even with the marker present', () => {
  const src = `
    // master-key derivation: TEST FIXTURE ONLY (pre-CH-10 legacy ciphertext)
    import { hkdfSync } from 'node:crypto';
    export function legacyFixture() { return hkdfSync('sha256', Buffer.alloc(32), Buffer.from('tenant:x'), Buffer.alloc(0), 32); }
  `;
  const verdict = checkTestFixtureDeriver('src/iam/some-fixture.test.ts', src, /* importedByNonTest */ true);
  assert.equal(verdict.ok, false, 'a listed file imported by a non-test file must not be accounted for even with the marker present');
  assert.ok(
    verdict.reasons.some((r) => r.includes('imported by a non-test')),
    `expected an "imported by a non-test source file" reason, got: ${verdict.reasons.join('; ')}`,
  );
});

test('evasion corpus: a TEST_FIXTURE_DERIVERS-listed path that is not .test.ts is still flagged, even with the marker present and no non-test importer', () => {
  const src = `
    // master-key derivation: TEST FIXTURE ONLY (pre-CH-10 legacy ciphertext)
    import { hkdfSync } from 'node:crypto';
    export function legacyFixture() { return hkdfSync('sha256', Buffer.alloc(32), Buffer.from('tenant:x'), Buffer.alloc(0), 32); }
  `;
  const verdict = checkTestFixtureDeriver('src/iam/some-fixture-helper.ts', src, false);
  assert.equal(verdict.ok, false, 'a listed path not ending .test.ts must not be accounted for');
  assert.ok(
    verdict.reasons.some((r) => r.includes('.test.ts')),
    `expected a ".test.ts" path reason, got: ${verdict.reasons.join('; ')}`,
  );
});

test('evasion corpus: a TEST_FIXTURE_DERIVERS-listed file satisfying all three conditions IS accounted for', () => {
  const src = `
    // master-key derivation: TEST FIXTURE ONLY (pre-CH-10 legacy ciphertext)
    import { hkdfSync } from 'node:crypto';
    function legacyFixture() { return hkdfSync('sha256', Buffer.alloc(32), Buffer.from('tenant:x'), Buffer.alloc(0), 32); }
  `;
  const verdict = checkTestFixtureDeriver('src/iam/some-fixture.test.ts', src, false);
  assert.equal(verdict.ok, true, `expected all three conditions to hold, got failures: ${verdict.reasons.join('; ')}`);
  assert.deepEqual(verdict.reasons, []);
});

test('evasion corpus: isImportedByNonTestFile detects a real (fabricated) non-test importer by basename, ignoring test-file importers', () => {
  // Builds a tiny synthetic file list in a scratch-only structure via the
  // SAME function under test, driven with in-memory content via a local
  // override — since isImportedByNonTestFile reads real files by design
  // (it must, to scan the actual repo), this proves the regex construction
  // itself against representative import forms rather than touching disk.
  const basenameNoExt = 'credential-loader.concurrent-upgrade.test';
  const specifierRe = new RegExp(`['"][^'"]*${basenameNoExt.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(\\.js)?['"]`);
  assert.ok(specifierRe.test(`import { x } from './credential-loader.concurrent-upgrade.test.js';`), 'relative .js-extension import must match');
  assert.ok(specifierRe.test(`require('../iam/credential-loader.concurrent-upgrade.test');`), 'extensionless require must match');
  assert.ok(!specifierRe.test(`import { x } from './credential-loader.js';`), 'an unrelated basename must not match');
});

// ── Registry disjointness (§12.2::11), info/context-label form ─────────────

test('CHARIOT::§12.2::11 — every registered consumer with a literal info/context label has a value unique across the registry', () => {
  const literalInfoValues = MASTER_KEY_CONSUMERS.filter(
    (c): c is typeof c & { info: { kind: 'literal'; value: string } } => c.info.kind === 'literal',
  ).map((c) => c.info.value);
  const asSet = new Set(literalInfoValues);
  assert.equal(
    asSet.size,
    literalInfoValues.length,
    `duplicate literal info/context label(s) across consumers: ${literalInfoValues.join(', ')}`,
  );
});

// ── Evasion corpus — string fixtures, not files. Each evasion form named
// in the finding above must
// be flagged by the scanner functions above; a prose-only fixture must not
// be. ─────────────────────────────────────────────────────────────────────

test('evasion corpus: TS destructured alias (`const { hkdfSync: h } = crypto`) is flagged', () => {
  const fixture = `
    import crypto from 'node:crypto';
    const { hkdfSync: h } = crypto;
    export function derive(master: Buffer, salt: Buffer, info: Buffer): Buffer {
      return Buffer.from(h('sha256', master, salt, info, 32));
    }
  `;
  assert.ok(hasTsDerivationCallSite(fixture), 'a destructured-and-renamed hkdfSync binding must still be flagged');
});

test('evasion corpus: TS indirect function alias (`const derive = crypto.hkdfSync`) is flagged', () => {
  const fixture = `
    import crypto from 'node:crypto';
    const derive = crypto.hkdfSync;
    export function go(master: Buffer, salt: Buffer, info: Buffer): Buffer {
      return Buffer.from(derive('sha256', master, salt, info, 32));
    }
  `;
  assert.ok(hasTsDerivationCallSite(fixture), 'an indirect function-reference alias of hkdfSync must still be flagged');
});

test('evasion corpus: TS `subtle.deriveBits` (Web Crypto path) is flagged', () => {
  const fixture = `
    import { webcrypto } from 'node:crypto';
    export async function derive(keyMaterial: CryptoKey, params: unknown): Promise<ArrayBuffer> {
      return webcrypto.subtle.deriveBits(params as never, keyMaterial, 256);
    }
  `;
  assert.ok(hasTsDerivationCallSite(fixture), 'a Web Crypto subtle.deriveBits call site must be flagged');
});

test('evasion corpus: TS renamed import binding a crypto-module subtle/webcrypto surface, with no other KDF identifier present, is still flagged', () => {
  // Deliberately does NOT literally spell deriveBits/hkdf anywhere — proves
  // the import+binding signal (not just the bare-identifier signal) does
  // real work, per the gate finding's explicit "import/require that binds
  // hkdf/hkdfSync/subtle/webcrypto" requirement.
  const fixture = `
    import { subtle as s } from 'node:crypto';
    export const keyDeriver = s;
  `;
  assert.ok(hasTsDerivationCallSite(fixture), 'an import binding the crypto module subtle surface must be flagged even under a renamed local binding');
});

test('evasion corpus: Rust renamed use alias (`use hkdf::Hkdf as K`) is flagged', () => {
  const fixture = `
    use hkdf::Hkdf as K;
    use sha2::Sha256;

    fn derive(secret: &[u8], salt: &[u8]) -> [u8; 32] {
        let hk = K::<Sha256>::new(Some(salt), secret);
        let mut okm = [0u8; 32];
        hk.expand(b"ctx", &mut okm).unwrap();
        okm
    }
  `;
  assert.ok(hasRustDerivationCallSite(fixture), 'a renamed `use hkdf::Hkdf as K` alias must still be flagged');
});

test('evasion corpus: Rust use-path alone (no .expand( call in the same fixture) is still flagged', () => {
  // Isolates the `use` path signal from the `.expand(` signal — proves
  // either one alone is sufficient, so removing/hiding one does not defeat
  // the other.
  const fixture = `
    use hkdf::Hkdf as K;
    fn make(secret: &[u8], salt: &[u8]) -> K<sha2::Sha256> {
        K::new(Some(salt), secret)
    }
  `;
  assert.ok(hasRustDerivationCallSite(fixture), 'the hkdf `use` path alone (renamed) must be sufficient to flag');
});

test('evasion corpus: prose-only fixture ("uses HKDF-SHA256" in a comment/doc string) is NOT flagged', () => {
  const tsFixture = `
    /**
     * This service delegates to the native binary, which uses HKDF-SHA256
     * key derivation internally. No derivation happens in this file — see
     * "hkdfSync" and "deriveBits" mentioned here only as prose, never code.
     */
    export function encrypt(plaintext: string): string {
      return plaintext; // placeholder — real implementation calls the native binary
    }
  `;
  assert.equal(hasTsDerivationCallSite(tsFixture), false, 'a comment/doc-only mention of HKDF/hkdfSync/deriveBits must not be flagged');

  const rustFixture = `
    // This module mirrors vault.rs, which uses HKDF-SHA256 ("hkdf" crate,
    // Hkdf::new, .expand(...)) for key derivation. No derivation call sites
    // exist in this file — only this descriptive comment does.
    fn noop() -> u8 { 0 }
  `;
  assert.equal(hasRustDerivationCallSite(rustFixture), false, 'a comment-only mention of hkdf/.expand( in Rust must not be flagged');
});

test('evasion corpus: a string-literal-only mention (not a comment, not code) is NOT flagged', () => {
  // Distinct from the comment case above: proves string-literal stripping,
  // not just comment stripping, is doing real work.
  const tsFixture = `
    export const NOTE = "this module never calls hkdfSync or deriveBits directly";
  `;
  assert.equal(hasTsDerivationCallSite(tsFixture), false, 'a KDF name appearing only inside a string literal must not be flagged');

  const rustFixture = `
    const NOTE: &str = "no hkdf usage here, see vault.rs instead";
  `;
  assert.equal(hasRustDerivationCallSite(rustFixture), false, 'a KDF name appearing only inside a Rust string literal must not be flagged');
});

// ── W10f follow-on: three surviving scan evasions (adversarial-review gate,
// same finding thread as the coverage-scan hardening above) ────────────────

test('evasion corpus: TS computed-property access (`crypto[\'hkdfSync\'](...)`) is flagged', () => {
  const fixture = `
    import crypto from 'node:crypto';
    export function derive(master: Buffer, salt: Buffer, info: Buffer): Buffer {
      return Buffer.from(crypto['hkdfSync'](master, salt, info, 32));
    }
  `;
  assert.ok(hasTsDerivationCallSite(fixture), 'crypto["hkdfSync"](...) via bracket access must be flagged');
});

test('evasion corpus: TS computed-property access with double quotes and whitespace (`c[ "deriveBits" ]`) is flagged', () => {
  const fixture = `
    import { webcrypto as c } from 'node:crypto';
    export async function derive(km: CryptoKey, params: unknown): Promise<ArrayBuffer> {
      const fn = c.subtle[ "deriveBits" ];
      return fn.call(c.subtle, params, km, 256);
    }
  `;
  assert.ok(hasTsDerivationCallSite(fixture), 'c.subtle[ "deriveBits" ] via whitespace-tolerant bracket access must be flagged');
});

test('evasion corpus: a KDF name inside a plain (non-bracket, non-call) string literal is still NOT flagged by the computed-access check', () => {
  // Negative control for the NEW signal specifically: proves the adjacency
  // requirement is doing real work, not just re-deriving the identifier
  // check's own result.
  const fixture = `export const NOTE = "hkdfSync and deriveBits are mentioned here as plain prose, not code";`;
  assert.equal(hasTsDerivationCallSite(fixture), false, 'a KDF name in a plain string with no bracket/call adjacency must not be flagged');
});

test('evasion corpus: TS template-literal interpolation (`${crypto.hkdfSync(...)}`) is flagged', () => {
  const fixture = `
    import crypto from 'node:crypto';
    export function derive(master: Buffer, salt: Buffer, info: Buffer): string {
      return \`derived:\${crypto.hkdfSync('sha256', master, salt, info, 32).toString('hex')}\`;
    }
  `;
  assert.ok(hasTsDerivationCallSite(fixture), 'a derivation call inside a template-literal ${...} interpolation must be flagged');
});

test('evasion corpus: nested template-literal interpolation (`${`inner ${crypto.hkdfSync(...)}`}`) is flagged', () => {
  const fixture = `
    import crypto from 'node:crypto';
    export function derive(master: Buffer, salt: Buffer, info: Buffer): string {
      return \`outer \${\`inner \${crypto.hkdfSync('sha256', master, salt, info, 32).toString('hex')}\`}\`;
    }
  `;
  assert.ok(hasTsDerivationCallSite(fixture), 'a derivation call nested two template-interpolation levels deep must still be flagged');
});

test('evasion corpus: template-literal text OUTSIDE any interpolation still does not falsely flag on prose', () => {
  // Negative control for the interpolation-recursion change specifically:
  // proves the literal TEXT portions of a template are still stripped as
  // quoted content (not accidentally turned into scannable code), while the
  // interpolation itself would be.
  const fixture = 'const NOTE = `this template mentions hkdfSync and deriveBits only as text, ${1 + 1} is the only interpolation`;';
  assert.equal(hasTsDerivationCallSite(fixture), false, 'template literal text outside ${...} must remain opaque quoted content');
});

test('evasion corpus: Rust `.expand (` with internal whitespace is flagged', () => {
  const fixture = `
    use hkdf::Hkdf;
    fn derive(secret: &[u8], salt: &[u8]) -> [u8; 32] {
        let hk = Hkdf::<sha2::Sha256>::new(Some(salt), secret);
        let mut okm = [0u8; 32];
        hk . expand (b"ctx", &mut okm).unwrap();
        okm
    }
  `;
  assert.ok(hasRustDerivationCallSite(fixture), 'hk . expand (...) with whitespace around the method call must be flagged');
});

test('evasion corpus: Rust `.expand_multi_info (` with internal whitespace is flagged', () => {
  const fixture = `
    use hkdf::Hkdf;
    fn derive(secret: &[u8], salt: &[u8]) -> [u8; 32] {
        let hk = Hkdf::<sha2::Sha256>::new(Some(salt), secret);
        let mut okm = [0u8; 32];
        hk.expand_multi_info (&[b"a", b"b"], &mut okm).unwrap();
        okm
    }
  `;
  assert.ok(hasRustDerivationCallSite(fixture), 'hk.expand_multi_info (...) with whitespace before the paren must be flagged');
});

test('evasion corpus: Rust bare `extract (` with whitespace is flagged', () => {
  const fixture = `
    use hkdf::Hkdf;
    fn extract_only(secret: &[u8], salt: &[u8]) -> Vec<u8> {
        let (prk, _) = Hkdf::<sha2::Sha256>::extract (Some(salt), secret);
        prk.to_vec()
    }
  `;
  assert.ok(hasRustDerivationCallSite(fixture), 'Hkdf::extract (...) with whitespace before the paren must be flagged');
});

// ── W10g follow-on: structural closure — three evasions the syntactic
// (identifier-based) detectors cannot be complete against, plus proof the
// structural rule surfaces a master-key-only file rather than silently
// passing it. ─────────────────────────────────────────────────────────────

test('evasion corpus: string-concatenated computed key (`const k = "hkdf"+"Sync"; crypto[k](...)`) is a structural candidate', () => {
  const fixture = `
    import crypto from 'node:crypto';
    export function derive(master: Buffer, salt: Buffer, info: Buffer): Buffer {
      const masterKey = master; // ENTERPRISE_MASTER_KEY, decoded upstream
      const k = 'hkdf' + 'Sync';
      return Buffer.from((crypto as any)[k]('sha256', masterKey, salt, info, 32));
    }
  `;
  const r = structuralTsSignals(fixture);
  assert.equal(r.masterKeyMaterial, true, 'fixture must reference master-key material (masterKey)');
  assert.equal(r.cryptoCapability, true, 'a string-concatenated computed key on crypto must still register a crypto-capability signal (bare identifier crypto + import)');
  assert.ok(r.signals.some((s) => s.startsWith('import:') || s === 'bare-identifier:crypto/webcrypto/subtle'), `expected an import or bare-identifier signal, got: ${r.signals.join(', ')}`);
});

test('evasion corpus: `Reflect.get(crypto, "hkdfSync")(...)` is a structural candidate', () => {
  const fixture = `
    import crypto from 'node:crypto';
    export function derive(masterKey: Buffer, salt: Buffer, info: Buffer): Buffer {
      const fn = Reflect.get(crypto, 'hkdfSync') as (...args: unknown[]) => ArrayBuffer;
      return Buffer.from(fn('sha256', masterKey, salt, info, 32));
    }
  `;
  const r = structuralTsSignals(fixture);
  assert.equal(r.masterKeyMaterial, true, 'fixture must reference master-key material (masterKey)');
  assert.equal(r.cryptoCapability, true, 'Reflect.get(crypto, ...) must register a crypto-capability signal');
  assert.ok(r.signals.includes('Reflect.get/apply'), `expected the Reflect.get/apply signal, got: ${r.signals.join(', ')}`);
});

test('evasion corpus: unicode-escaped identifier (`crypto.\\u0068kdfSync`) is flagged by the identifier-based detector after decoding', () => {
  // h is 'h' — crypto.hkdfSync is byte-for-byte what the TS/JS
  // parser treats as crypto.hkdfSync. Written here as a literal backslash
  // sequence (not a real escape in THIS file, since this is itself TS
  // source) so the fixture string contains the two raw characters `\`+`u`.
  const fixture = "import crypto from 'node:crypto';\nexport function derive(masterKey: Buffer, salt: Buffer, info: Buffer) {\n  return Buffer.from(crypto.\\u0068kdfSync('sha256', masterKey, salt, info, 32));\n}\n";
  assert.ok(fixture.includes('\\u0068'), 'fixture must contain the literal escape sequence, not a pre-decoded character (sanity check on the fixture itself)');
  assert.ok(hasTsDerivationCallSite(fixture), 'a \\u-escaped hkdfSync identifier must be flagged once decoded');
});

test('evasion corpus: unicode-escaped identifier via `\\u{...}` brace form is flagged by the identifier-based detector after decoding', () => {
  // \u{68} is also 'h' — the brace form of the same escape, valid in
  // template literals and (per current TC39 grammar) identifiers.
  const fixture = "import crypto from 'node:crypto';\nexport function derive(masterKey: Buffer, salt: Buffer, info: Buffer) {\n  return Buffer.from(crypto.\\u{68}kdfSync('sha256', masterKey, salt, info, 32));\n}\n";
  assert.ok(hasTsDerivationCallSite(fixture), 'a \\u{...}-escaped hkdfSync identifier must be flagged once decoded');
});

test('evasion corpus: `globalThis.crypto.subtle.deriveBits` with NO import is flagged (both detectors)', () => {
  const fixture = `
    export async function derive(masterKey: CryptoKey, params: unknown): Promise<ArrayBuffer> {
      // No import of 'node:crypto'/'crypto' anywhere — the Web Crypto
      // global needs none.
      return globalThis.crypto.subtle.deriveBits(params as never, masterKey, 256);
    }
  `;
  assert.ok(hasTsDerivationCallSite(fixture), 'globalThis.crypto.subtle.deriveBits must be flagged by the identifier-based detector (bare "deriveBits")');
  const r = structuralTsSignals(fixture);
  assert.equal(r.masterKeyMaterial, true);
  assert.equal(r.cryptoCapability, true, 'globalThis...crypto with no import must still register a crypto-capability signal');
  assert.ok(r.signals.includes('globalThis..crypto'), `expected the globalThis..crypto signal, got: ${r.signals.join(', ')}`);
});

test('evasion corpus: master-key material with NO crypto capability reference is a delegator-candidate, not silently passed', () => {
  // A config reader that only forwards ENTERPRISE_MASTER_KEY to another
  // process/service — no import, no bare crypto/webcrypto/subtle
  // identifier, no globalThis...crypto, no Reflect.get/apply.
  const fixture = `
    export function forwardMasterKeyToSubprocess(env: Record<string, string>): void {
      env.ENTERPRISE_MASTER_KEY = process.env.ENTERPRISE_MASTER_KEY ?? '';
    }
  `;
  const r = structuralTsSignals(fixture);
  assert.equal(r.masterKeyMaterial, true, 'fixture must reference master-key material (ENTERPRISE_MASTER_KEY)');
  assert.equal(r.cryptoCapability, false, 'a config reader with no crypto reference must NOT register any crypto-capability signal');
  assert.deepEqual(r.signals, [], 'no capability signals expected');
  // This is exactly the shape the coverage test classifies as
  // 'delegator-candidate (master-key material referenced, no crypto
  // capability signal)' when the file is not already in
  // VALIDATION_ONLY_FILES/DOCUMENTED_DELEGATORS/etc — see that test, which
  // proves this classification is never silently skipped for a real file.
});

test('evasion corpus: prose-only fixture with a crypto import but no master-key material is NOT a structural candidate', () => {
  const fixture = `
    import crypto from 'node:crypto';
    export function hashSomething(x: string): string {
      return crypto.createHash('sha256').update(x).digest('hex');
    }
  `;
  const r = structuralTsSignals(fixture);
  assert.equal(r.masterKeyMaterial, false, 'no master-key material referenced in this fixture');
  // cryptoCapability may be true (a real crypto import) — irrelevant, since
  // masterKeyMaterial is false the AND-rule never makes this a candidate.
});
