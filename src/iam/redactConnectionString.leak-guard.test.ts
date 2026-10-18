/**
 * CHARIOT rulings item 126 (unit W-IAM-REDACT) — grep-guard: no source
 * file in `src/` may get a raw connection-string identifier
 * (`MONGODB_URI`/`REDIS_URL` env reads, or the conventional local
 * variable names for those reads, with or without a property path —
 * `cfg.mongoUri`, `process.env.MONGODB_URI`, `x['MONGODB_URI']`) into a
 * log line, thrown message, or string built from one, WITHOUT routing it
 * through `redactConnectionString()` first. Repo-wide, not scoped to any
 * one file — the root cause this unit closed (an unredacted connection-
 * string variable interpolated directly into a thrown Error message in
 * `src/iam/bootstrap.ts`) was exactly this shape, and a THIRD, previously
 * undiscovered instance of it (`src/bin/chariot.ts`'s `vault migrate`
 * command) was found only once this guard existed.
 *
 * chariot-verify-wave10 finding (fixed, kept for the record): the
 * scanned-file path was computed via a raw `.slice(repoRoot.length + 1)`,
 * but `fileURLToPath()` on a directory URL returns a path WITH a
 * trailing separator, so the `+1` skipped one byte too many
 * (`src/iam/bootstrap.ts` became `rc/iam/bootstrap.ts`), and the
 * self-exemption string compare against the full `src/...` path
 * therefore never matched under the real compiled/roll-call execution
 * context — this file's OWN prose/fixture lines were flagged as if they
 * were a real leak. Fixed by using `node:path`'s `relative()` against a
 * `src/` root resolved from THIS file's own location (works whether this
 * file is executing from `src/` via a loader or from its compiled
 * `dist/` location — both sit exactly two directory levels below the
 * repo root), and by self-exempting via `basename()` instead of a
 * path-prefix string. KEPT in this revision.
 *
 * chariot-verify-wave11 (review gate finding, thread
 * 01a06d96-0132-71b2-92f4-a87dd7611393) finding: the ORIGINAL detector
 * matched only the exact bare shape `${mongoUri}` / `${process.env
 * .MONGODB_URI}` — its own doc comment admitted `${cfg.mongoUri}`
 * (property-path interpolation) and `'at ' + mongoUri` (string
 * concatenation) would NOT match. Both are real, equally leaky shapes.
 * This revision adds three independent detectors (a)-(c) below, each
 * with its own "fires on the unsafe shape / does not fire on the
 * `redactConnectionString(...)`-wrapped shape" sanity test:
 *
 *   (a) TEMPLATE INTERPOLATION, any property/bracket path:
 *       `\$\{([^}]*)\}` — for each `${...}` block found, flag it if the
 *       block's content contains one of the four identifiers (as a word,
 *       so `cfg.mongoUri`, `process.env.MONGODB_URI`, and
 *       `x['MONGODB_URI']` all match — the quote/bracket/dot characters
 *       around the identifier are non-word so `\b` still finds it) AND
 *       the block's content does NOT also contain the literal text
 *       `redactConnectionString(`. Each `${...}` block in a line is
 *       checked independently, so `${redactConnectionString(a)}
 *       ${cfg.mongoUri}` still fires (the SECOND block has no wrapper).
 *
 *   (b) STRING CONCATENATION: `+` adjacent, on either side, to one of
 *       the four identifiers with any dotted/bracketed property path
 *       (`+ mongoUri`, `+ cfg.mongoUri`, `mongoUri +`,
 *       `+ process.env.MONGODB_URI`). The character classes used for the
 *       property-path portion (`[\w.]`) never include `(`, so a
 *       genuinely wrapped form — `+ redactConnectionString(cfg.mongoUri)`
 *       — cannot match: the scan for the identifier immediately
 *       following the `+`-and-property-path run hits the `(` of
 *       `redactConnectionString(` and stops, never reaching the
 *       identifier on the other side of that paren. Verified by an
 *       explicit sanity test, not merely reasoned about.
 *
 *   (c) LOG/CONSOLE SINK, bare identifier as a call argument:
 *       `\b(?:console\.\w+|log|warn|error|info|debug)\(([^)]*)\)` — for
 *       each such call found, flag it if the captured argument text
 *       contains one of the four identifiers AND does not also contain
 *       `redactConnectionString(`. Deliberately narrow to this sink-name
 *       list (matches the exact set named in the review finding) rather
 *       than every function call in the tree.
 *
 * Legitimate non-log uses are excluded BY THE SHAPE of the detectors
 * above, never by a per-file allowlist:
 *   - A plain assignment (`const mongoUri = process.env.MONGODB_URI;`)
 *     has no `${...}`, no adjacent `+`, and is not an argument to one of
 *     the four sink names — none of (a)/(b)/(c) match it.
 *   - A constructor/connect call (`new MongoClient(mongoUri)`,
 *     `createClient({ url: redisUrl })`, `client.connect()`) is not one
 *     of the sink names (c) is scoped to, and does not appear inside a
 *     `${...}` or beside a `+` — none of (a)/(b)/(c) match it.
 *   - `redactConnectionString(mongoUri)` itself (the helper's own
 *     definition and every correct call site) is the literal exemption
 *     text (a)/(b)/(c) all check for.
 *
 * Comments (`//` and `/* *\/`) are stripped before matching (see
 * `stripComments` below), so a doc comment or prose description that
 * itself quotes a flagged shape — as this very header does, repeatedly —
 * can never trip the guard in ANY file. String/template literal CONTENTS
 * are left untouched by the stripper, so a real interpolation inside
 * real code is still detected, and a `//`/`/*` sequence inside an
 * unrelated string (e.g. a URL literal) is never mistaken for a comment.
 *
 * chariot-verify-wave12 (rulings item 136) hardening — three more real
 * gaps, each with its own fires/does-not-fire sanity pair:
 *
 *   (1) SINK_CALL's argument capture previously used `([^)]*)`, which
 *       truncates at the FIRST `)` — `log(fmt(x), mongoUri)` escaped,
 *       since the capture stopped at `fmt(x)`'s own closing paren and
 *       never saw the real `mongoUri` argument after it. Replaced with
 *       `extractBalancedArgs()`, a small depth-counting scanner (not a
 *       regex) over the call's full argument span: it tracks paren
 *       depth (incrementing on `(`, decrementing on `)`, stopping when
 *       depth returns to 0) and skips over quoted-string contents so a
 *       `)` inside a string is never mistaken for the call's own close.
 *
 *   (2) Concatenation now also covers optional chaining (`cfg?.mongoUri`)
 *       and bracket/index access (`cfg['MONGODB_URI']`) adjacent to `+`
 *       — the property-path character class widened from `[\w.]` to
 *       `[\w.?[\]'"]` (adds `?`, `[`, `]`, and quote characters). The
 *       wrapped-form exemption still holds for the same reason as
 *       before: `(` is still excluded from the class, so
 *       `+ redactConnectionString(cfg['MONGODB_URI'])` cannot match —
 *       the scan hits the `(` of the wrapper and stops.
 *
 *   (3) The sink-name list gains `child` (a `.child(...)` scoped-logger
 *       call, e.g. `logger.child({ mongoUri })`) and `emit`. An OBJECT-
 *       LITERAL argument carrying the bare identifier — `emit('x', {
 *       mongoUri })` (shorthand) or `{ uri: mongoUri }` (property value)
 *       — is caught with no extra logic: `hasUnwrappedIdentifier()`
 *       already scans the WHOLE (now balanced, per (1)) argument span
 *       for the bare identifier text, which appears unchanged inside
 *       either object-literal shape.
 *
 * Run (after tsc): node --test dist/iam/redactConnectionString.leak-guard.test.js
 * Also runnable directly, single-file, via Node's native TS stripping:
 * node --test src/iam/redactConnectionString.leak-guard.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, extname, relative, basename } from 'node:path';
import { fileURLToPath } from 'node:url';

// Two directory levels above THIS file's own location is the repo root,
// whether this file is currently running from `src/iam/...` (a ts loader)
// or its compiled `dist/iam/...` — both are exactly two levels below the
// repo root. The scan target is always the real `src/` tree regardless of
// which of those two locations this file itself is executing from.
const repoRoot = fileURLToPath(new URL('../..', import.meta.url));
const srcRoot = join(repoRoot, 'src');

// This test file itself intentionally references the flagged shapes — in
// prose describing what the detectors catch, and in the sanity tests'
// own fixture strings below — so it is excluded from the scan it
// performs. It is not a log/error-message call site. Matched by
// basename, not a path-prefix string (see the chariot-verify-wave10
// finding above for why a prefix string broke).
const SELF_BASENAME = 'redactConnectionString.leak-guard.test.ts';

const IDENTIFIER_SOURCE = 'mongoUri|redisUrl|MONGODB_URI|REDIS_URL';
const IDENTIFIER_RE = new RegExp(`\\b(?:${IDENTIFIER_SOURCE})\\b`);
const WRAPPED = 'redactConnectionString(';

// A bracket-access property read whose KEY is one of the four identifier
// names — `x['MONGODB_URI']` — is a real identifier reference even
// though it is syntactically a quoted string. Checked BEFORE the general
// quoted-span strip below (which would otherwise remove it and produce a
// false negative for exactly the bracket form rulings item 126 requires).
const BRACKET_ACCESS_RE = new RegExp(`\\[\\s*['"](?:${IDENTIFIER_SOURCE})['"]\\s*\\]`);

/**
 * Remove single/double-quoted string-literal SPANS (handling escapes).
 * chariot-verify-wave11 finding: without this, a `${...}` interpolation
 * block containing a plain string that merely MENTIONS one of the four
 * names as human-readable prose — e.g. a ternary's label strings,
 * `'external (REDIS_URL)'` — is a false positive: the value never
 * carries the real env var, only its name as text for a human reader.
 * The bracket-access form above is special-cased BEFORE this strip runs.
 */
function stripQuotedSpans(text: string): string {
  return text.replace(/'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"/g, '');
}

/** (a) — see header comment. */
const INTERPOLATION_BLOCK = /\$\{([^}]*)\}/g;

/**
 * (b) — see header comment. Both directions of `+` adjacency. The
 * property-path character class covers a dotted path (`cfg.mongoUri`),
 * optional chaining (`cfg?.mongoUri`), and bracket/index access
 * (`cfg['MONGODB_URI']`) — `(` is deliberately excluded so a
 * `redactConnectionString(...)`-wrapped value can never match (see the
 * header comment's item (2) for the full trace of why).
 */
const PROPERTY_PATH = `[\\w.?\\[\\]'"]*`;
const CONCAT_AFTER_PLUS = new RegExp(`\\+\\s*${PROPERTY_PATH}\\b(?:${IDENTIFIER_SOURCE})\\b`);
const CONCAT_BEFORE_PLUS = new RegExp(`\\b(?:${IDENTIFIER_SOURCE})\\b${PROPERTY_PATH}\\s*\\+`);

/**
 * (c) — see header comment. Sink-name list: `console.<anything>`, the
 * bare log-level names, plus `child` (a scoped-logger call,
 * `logger.child({ mongoUri })`) and `emit`. A bare name also matches as
 * the tail of a dotted chain (`moduleLog.warn(` — the `\b` before the
 * name is satisfied by the preceding `.`), so no separate `\w+\.child`
 * form is needed alongside the bare `child` alternative.
 */
const SINK_NAME = /\b(?:console\.\w+|child|log|warn|error|info|debug|emit)\(/g;

/** True when `text` names one of the four connection-string identifiers, unwrapped by the redaction helper. */
function hasUnwrappedIdentifier(text: string): boolean {
  if (text.includes(WRAPPED)) return false;
  if (BRACKET_ACCESS_RE.test(text)) return true;
  return IDENTIFIER_RE.test(stripQuotedSpans(text));
}

/**
 * (1) — see header comment. Depth-counting scanner (not a regex) over a
 * call's argument span, starting right after its opening `(` (already
 * consumed by the caller). Tracks paren depth so a nested call's own
 * closing `)` — `log(fmt(x), mongoUri)` — does not end the scan early,
 * and skips over quoted-string contents so a `)` inside a string
 * literal is never mistaken for the call's own close. Returns the full
 * argument text (excluding the final closing paren).
 */
function extractBalancedArgs(line: string, openParenIndex: number): string {
  let depth = 1;
  let i = openParenIndex + 1;
  let out = '';
  const n = line.length;
  while (i < n && depth > 0) {
    const c = line[i];
    if (c === '\'' || c === '"' || c === '`') {
      const quote = c;
      out += c;
      i++;
      while (i < n && line[i] !== quote) {
        if (line[i] === '\\') {
          out += line[i];
          i++;
          if (i < n) { out += line[i]; i++; }
          continue;
        }
        out += line[i];
        i++;
      }
      if (i < n) { out += line[i]; i++; }
      continue;
    }
    if (c === '(') {
      depth++;
      out += c;
      i++;
      continue;
    }
    if (c === ')') {
      depth--;
      if (depth === 0) break;
      out += c;
      i++;
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

/**
 * Split a call's already-balanced argument text into its TOP-LEVEL
 * (depth-0) comma-separated arguments, tracking `(`/`)`, `[`/`]`, AND
 * `{`/`}` depth together (an object- or array-literal argument's own
 * internal commas must not split it), and skipping over quoted-string
 * contents the same way `extractBalancedArgs` does. Checking each
 * top-level argument independently (rather than the whole args blob at
 * once) closes a real gap the naive whole-blob check has: a call with
 * ONE safely-wrapped argument and a SEPARATE, still-raw argument —
 * `log(redactConnectionString(a), mongoUri)` — must still be flagged for
 * the second argument; a single `text.includes(WRAPPED)` check over the
 * whole blob would have wrongly exempted the entire call.
 */
function splitTopLevelArgs(text: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let current = '';
  let i = 0;
  const n = text.length;
  while (i < n) {
    const c = text[i];
    if (c === '\'' || c === '"' || c === '`') {
      const quote = c;
      current += c;
      i++;
      while (i < n && text[i] !== quote) {
        if (text[i] === '\\') {
          current += text[i];
          i++;
          if (i < n) { current += text[i]; i++; }
          continue;
        }
        current += text[i];
        i++;
      }
      if (i < n) { current += text[i]; i++; }
      continue;
    }
    if (c === '(' || c === '[' || c === '{') { depth++; current += c; i++; continue; }
    if (c === ')' || c === ']' || c === '}') { depth--; current += c; i++; continue; }
    if (c === ',' && depth === 0) {
      parts.push(current);
      current = '';
      i++;
      continue;
    }
    current += c;
    i++;
  }
  if (current.trim() !== '' || parts.length > 0) parts.push(current);
  return parts;
}

function findUnsafeInterpolation(line: string): boolean {
  INTERPOLATION_BLOCK.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = INTERPOLATION_BLOCK.exec(line)) !== null) {
    if (hasUnwrappedIdentifier(m[1])) return true;
  }
  return false;
}

function findUnsafeConcatenation(line: string): boolean {
  if (CONCAT_AFTER_PLUS.test(line) && !line.includes(WRAPPED)) return true;
  if (CONCAT_BEFORE_PLUS.test(line) && !line.includes(WRAPPED)) return true;
  return false;
}

function findUnsafeSinkCall(line: string): boolean {
  SINK_NAME.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = SINK_NAME.exec(line)) !== null) {
    const openParenIndex = m.index + m[0].length - 1;
    const args = extractBalancedArgs(line, openParenIndex);
    for (const arg of splitTopLevelArgs(args)) {
      if (hasUnwrappedIdentifier(arg)) return true;
    }
  }
  return false;
}

/**
 * Strip `//` line comments and `/* *\/` block comments from `src`,
 * leaving string and template-literal CONTENTS untouched (a `//` or `/*`
 * sequence inside a quoted string, e.g. a URL literal, is not mistaken
 * for a comment start; a real `${...}` interpolation inside a real
 * template literal survives for the detectors above to still catch).
 * Newlines inside a stripped block comment are preserved so line numbers
 * in the caller's line-by-line scan stay accurate.
 */
function stripComments(src: string): string {
  let out = '';
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];
    const c2 = src[i + 1];
    if (c === '/' && c2 === '/') {
      while (i < n && src[i] !== '\n') i++;
      continue;
    }
    if (c === '/' && c2 === '*') {
      i += 2;
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) {
        if (src[i] === '\n') out += '\n';
        i++;
      }
      i += 2;
      continue;
    }
    if (c === '\'' || c === '"' || c === '`') {
      const quote = c;
      out += c;
      i++;
      while (i < n && src[i] !== quote) {
        if (src[i] === '\\') {
          out += src[i];
          i++;
          if (i < n) { out += src[i]; i++; }
          continue;
        }
        out += src[i];
        i++;
      }
      if (i < n) { out += src[i]; i++; }
      continue;
    }
    out += c;
    i++;
  }
  return out;
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
    const st = statSync(full);
    if (st.isDirectory()) {
      listSourceFiles(full, out);
    } else if (extname(entry) === '.ts') {
      out.push(full);
    }
  }
}

test('§rulings-126 leak-guard: the scanner actually resolved the real src/ tree (not an empty or wrong directory)', () => {
  const files: string[] = [];
  listSourceFiles(srcRoot, files);
  assert.ok(files.length > 0, `expected at least one .ts file under ${srcRoot}, found none — the path resolution is broken`);
  const relPaths = files.map((f) => relative(srcRoot, f).split('\\').join('/'));
  assert.ok(relPaths.includes('iam/bootstrap.ts'), `expected iam/bootstrap.ts among the scanned files — got a sample: ${relPaths.slice(0, 5).join(', ')}`);
});

test('§rulings-126 leak-guard: no src/ file interpolates, concatenates, or logs a raw MONGODB_URI/REDIS_URL/mongoUri/redisUrl identifier (any property path) unredacted', () => {
  const files: string[] = [];
  listSourceFiles(srcRoot, files);

  const flagged: Array<{ file: string; line: number; reason: string; snippet: string }> = [];
  for (const absPath of files) {
    if (basename(absPath) === SELF_BASENAME) continue;
    const relPath = relative(srcRoot, absPath).split('\\').join('/');
    const src = readFileSync(absPath, 'utf8');
    const stripped = stripComments(src);
    const lines = stripped.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (findUnsafeInterpolation(line)) {
        flagged.push({ file: relPath, line: i + 1, reason: 'interpolation', snippet: line.trim() });
        continue;
      }
      if (findUnsafeConcatenation(line)) {
        flagged.push({ file: relPath, line: i + 1, reason: 'concatenation', snippet: line.trim() });
        continue;
      }
      if (findUnsafeSinkCall(line)) {
        flagged.push({ file: relPath, line: i + 1, reason: 'sink-call', snippet: line.trim() });
      }
    }
  }

  assert.deepEqual(
    flagged,
    [],
    flagged.length === 0
      ? ''
      : `unredacted connection-string usage found — wrap with redactConnectionString():\n${flagged
          .map((f) => `  - [${f.reason}] ${f.file}:${f.line}: ${f.snippet}`)
          .join('\n')}`,
  );
});

// ── (a) template interpolation, any property path ──────────────────────

test('§rulings-126 leak-guard (a): fires on bare and property-path interpolation', () => {
  for (const line of [
    'throw new Error(`unavailable at ${mongoUri}`);',
    'log.warn(`unavailable at ${cfg.mongoUri}`);',
    'log.warn(`unavailable at ${process.env.MONGODB_URI}`);',
    "log.warn(`unavailable at ${x['MONGODB_URI']}`);",
    'log.warn(`unavailable at ${state.redisUrl}`);',
  ]) {
    assert.ok(findUnsafeInterpolation(line), `expected a hit for: ${line}`);
  }
});

test('§rulings-126 leak-guard (a): does NOT fire on the redactConnectionString(...)-wrapped form, including mixed with a second unwrapped block', () => {
  assert.ok(!findUnsafeInterpolation('log.warn(`at ${redactConnectionString(mongoUri)}`);'), 'a wrapped bare identifier must not fire');
  assert.ok(!findUnsafeInterpolation('log.warn(`at ${redactConnectionString(x.mongoUri)}`);'), 'a wrapped property-path identifier must not fire');
  assert.ok(findUnsafeInterpolation('log.warn(`${redactConnectionString(a)} ${cfg.mongoUri}`);'), 'a SECOND, unwrapped interpolation block on the same line must still fire');
});

// ── (b) string concatenation ────────────────────────────────────────────

test('§rulings-126 leak-guard (b): fires on concatenation in both directions, bare and property-path', () => {
  for (const line of [
    "throw new Error('unavailable at ' + mongoUri);",
    "throw new Error('unavailable at ' + cfg.mongoUri);",
    "throw new Error('unavailable at ' + process.env.MONGODB_URI);",
    'throw new Error(mongoUri + " is unavailable");',
    'throw new Error(cfg.redisUrl + " is unavailable");',
  ]) {
    assert.ok(findUnsafeConcatenation(line), `expected a hit for: ${line}`);
  }
});

test('§rulings-126 leak-guard (b): does NOT fire when the concatenated value is redactConnectionString(...)-wrapped', () => {
  for (const line of [
    "throw new Error('unavailable at ' + redactConnectionString(mongoUri));",
    "throw new Error('unavailable at ' + redactConnectionString(cfg.mongoUri));",
    'throw new Error(redactConnectionString(mongoUri) + " is unavailable");',
  ]) {
    assert.ok(!findUnsafeConcatenation(line), `expected NO hit for: ${line}`);
  }
});

// ── (c) log/console sink, bare argument ─────────────────────────────────

test('§rulings-126 leak-guard (c): fires when a bare (or property-path) identifier is passed directly to a named sink', () => {
  for (const line of [
    'console.log(mongoUri);',
    'console.error(cfg.mongoUri);',
    'log(redisUrl);',
    'warn(process.env.MONGODB_URI);',
    'error({ redisUrl });',
    "info('mongo:', mongoUri);",
  ]) {
    assert.ok(findUnsafeSinkCall(line), `expected a hit for: ${line}`);
  }
});

test('§rulings-126 leak-guard (c): does NOT fire when the sink argument is redactConnectionString(...)-wrapped', () => {
  for (const line of [
    'console.log(redactConnectionString(mongoUri));',
    'warn(redactConnectionString(cfg.mongoUri));',
    "info('mongo:', redactConnectionString(mongoUri));",
  ]) {
    assert.ok(!findUnsafeSinkCall(line), `expected NO hit for: ${line}`);
  }
});

// ── (1) balanced-parenthesis argument capture (a nested call must not hide a later argument) ──

test('§rulings-126 leak-guard (1): a nested call inside the sink\'s arguments does not hide a later bare identifier argument', () => {
  for (const line of [
    'log(fmt(x), mongoUri);',
    'warn(describe(a, b), cfg.mongoUri);',
    "error(JSON.stringify({ a: 1 }), process.env.MONGODB_URI);",
  ]) {
    assert.ok(findUnsafeSinkCall(line), `expected a hit for: ${line}`);
  }
});

test('§rulings-126 leak-guard (1): does NOT fire when that same later argument is redactConnectionString(...)-wrapped', () => {
  for (const line of [
    'log(fmt(x), redactConnectionString(mongoUri));',
    'warn(describe(a, b), redactConnectionString(cfg.mongoUri));',
  ]) {
    assert.ok(!findUnsafeSinkCall(line), `expected NO hit for: ${line}`);
  }
});

test('§rulings-126 leak-guard (1): a call with ONE wrapped argument and a SEPARATE raw argument still fires for the raw one (per-argument check, not a whole-blob check)', () => {
  assert.ok(findUnsafeSinkCall('log(redactConnectionString(a), mongoUri);'), 'the second, still-raw argument must be caught even though the first argument is safely wrapped');
});

// ── (2) concatenation through optional chaining and bracket/index access ──

test('§rulings-126 leak-guard (2): fires on optional chaining and bracket-access adjacent to +, in both directions', () => {
  for (const line of [
    "throw new Error('at ' + cfg?.mongoUri);",
    "throw new Error('at ' + cfg['MONGODB_URI']);",
    "throw new Error(cfg?.mongoUri + ' unavailable');",
    "throw new Error(cfg['MONGODB_URI'] + ' unavailable');",
  ]) {
    assert.ok(findUnsafeConcatenation(line), `expected a hit for: ${line}`);
  }
});

test('§rulings-126 leak-guard (2): does NOT fire when the optional-chained/bracket-accessed value is redactConnectionString(...)-wrapped', () => {
  for (const line of [
    "throw new Error('at ' + redactConnectionString(cfg?.mongoUri));",
    "throw new Error('at ' + redactConnectionString(cfg['MONGODB_URI']));",
    "throw new Error(redactConnectionString(cfg['MONGODB_URI']) + ' unavailable');",
  ]) {
    assert.ok(!findUnsafeConcatenation(line), `expected NO hit for: ${line}`);
  }
});

// ── (3) .child(/emit( sinks, and an object-literal argument carrying the identifier ──

test('§rulings-126 leak-guard (3): fires on a .child(...) scoped-logger call and an emit(...) call whose object-literal argument carries the identifier', () => {
  for (const line of [
    'logger.child({ mongoUri }).info("ready");',
    "child({ redisUrl });",
    "emit('db.error', { mongoUri });",
    "emit('db.error', { uri: mongoUri });",
  ]) {
    assert.ok(findUnsafeSinkCall(line), `expected a hit for: ${line}`);
  }
});

test('§rulings-126 leak-guard (3): does NOT fire when the .child(/emit( object-literal value is redactConnectionString(...)-wrapped', () => {
  for (const line of [
    'logger.child({ mongoUri: redactConnectionString(mongoUri) }).info("ready");',
    "emit('db.error', { uri: redactConnectionString(mongoUri) });",
  ]) {
    assert.ok(!findUnsafeSinkCall(line), `expected NO hit for: ${line}`);
  }
});

// ── exclusion-by-construction: legitimate non-log uses never match ANY detector ──

test('§rulings-126 leak-guard: legitimate non-log uses (assignment, constructor, connect) never match any detector', () => {
  for (const line of [
    'const mongoUri = process.env.MONGODB_URI;',
    "const redisUrl = process.env.REDIS_URL ?? '';",
    'const mongoClient = new MongoClient(mongoUri, { serverSelectionTimeoutMS: 5000 });',
    'const client = createClient({ url: redisUrl });',
    'await mongoClient.connect();',
    'return resolveEnterpriseRedisClient(redisUrl, warn);',
  ]) {
    assert.ok(!findUnsafeInterpolation(line), `assignment/constructor/connect must not match (a): ${line}`);
    assert.ok(!findUnsafeConcatenation(line), `assignment/constructor/connect must not match (b): ${line}`);
    assert.ok(!findUnsafeSinkCall(line), `assignment/constructor/connect must not match (c): ${line}`);
  }
});

// ── stripComments (unchanged behavior from the prior revision) ─────────

test('§rulings-126 leak-guard sanity: stripComments removes a doc-comment mention of a flagged shape but preserves a real interpolation in code', () => {
  const src = [
    '/**',
    ' * this comment mentions ${mongoUri} in prose',
    ' */',
    '// another comment with ${redisUrl}',
    'const x = `real code ${mongoUri} here`;',
    "const y = 'a string with // not a comment';",
  ].join('\n');
  const stripped = stripComments(src);
  assert.ok(!stripped.includes('this comment mentions'), 'block-comment prose must be removed');
  assert.ok(!stripped.includes('another comment with'), 'line-comment prose must be removed');
  assert.ok(stripped.includes('real code ${mongoUri} here'), 'a genuine template-literal interpolation in real code must survive stripping');
  assert.ok(stripped.includes('a string with // not a comment'), 'a // sequence inside a string literal must not be treated as a comment start');
});

// ── stripQuotedSpans / bracket-access special-case ──────────────────────

test('§rulings-126 leak-guard sanity: a string LITERAL that merely mentions a name as prose is not flagged, but a bracket-access KEY with the same name still is', () => {
  // chariot-verify-wave11 real-world case found in src/engine/bin/setup.ts:
  // a ternary whose two branches are human-readable LABEL strings that
  // happen to mention "REDIS_URL" as text — never the actual env var value.
  const proseLabel = "redisMode === 'external' ? 'external (REDIS_URL)' : 'in-process-shim (set a reachable REDIS_URL)'";
  assert.ok(!hasUnwrappedIdentifier(proseLabel), 'a string literal mentioning the name as prose must not be flagged');

  assert.ok(hasUnwrappedIdentifier("x['MONGODB_URI']"), 'a bracket-access property read by that exact name must still be flagged');
  assert.ok(!hasUnwrappedIdentifier("redactConnectionString(x['MONGODB_URI'])"), 'a wrapped bracket-access read must not be flagged');
  assert.ok(!hasUnwrappedIdentifier("'Set REDIS_URL in your environment to enable Redis.'"), 'a bare prose string (no bracket access, no real reference) must not be flagged');
});
