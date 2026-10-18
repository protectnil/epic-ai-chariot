/**
 * Sealed-snapshot seam regression eval — the TypeScript seam MUST represent the full Rust
 * NAPI contract for the sealed-snapshot boundary.
 *
 * The defect: `nativeEdge.ts` declared `unsealAndVerifySnapshot` with SEVEN
 * parameters while `edge_snapshot.rs:361` exports EIGHT. The missing one is
 * `min_epoch`, the CHARIOT §8.6 anti-rollback floor. `edge_snapshot.rs:261`
 * states that a replayed old-but-legitimately-signed bundle is self-consistent
 * — its original salt/aad/signature all verify — so the ONLY thing that stops a
 * rollback is comparing the bundle epoch against a floor sourced OUTSIDE the
 * bundle. A 7-parameter type made that floor unpassable from TypeScript.
 * `edgeUnpackSnapshot` was likewise 2-vs-3 (the verify-before-load `receipt`),
 * and `NativeUnsealedSnapshot` omitted `receipt` entirely.
 *
 * WHY IT LIVES IN evals/ AND NOT src/:
 * this eval reads `native/src/*.rs`. `package.json` `files:` ships only
 * ['dist', 'native/*.node', 'native/integrity.json', ...] and `.npmignore:19`
 * excludes `native/src/`. A copy compiled into `dist/` would therefore ship to
 * consumers with its inputs absent and throw on every install. `evals/` is
 * git-tracked, is NOT in `files:`, and is never compiled into `dist` — the same
 * placement the ch54-* deploy evals already use.
 *
 * WHY SOURCE-CONFORMANCE AND NOT RUNTIME:
 * NAPI exports report `Function.prototype.length === 0` for every binding
 * (measured: unsealAndVerifySnapshot, edgeUnpackSnapshot, EdgeShardHandle.load,
 * DenseEncoder.load all report arity 0), so arity cannot be reflected at
 * runtime. `hasEdgeSurface` only tests `typeof x === 'function'`, which a
 * 7-parameter binary passes. The Rust source is the only available oracle and
 * is the authoritative one — it is what actually enforces the contract.
 *
 * ANTI-BYPASS: a parser that silently misses an export would compare two
 * incomplete maps and pass. So the discovered export set is asserted against a
 * PINNED roster below. Any Rust export added, removed, renamed, or written in a
 * form the scanner cannot read changes that set and fails this eval loudly.
 * Parameter lists are read with a balanced-paren scan (not a regex), so types
 * containing `)` — `Option<Vec<(u32, f64)>>` — cannot truncate a signature, and
 * `js_name = "..."` overrides are honoured because three real exports use them
 * (`bien_serializer.rs:378,387,398`); the naive snake->camel mapping produces
 * `napiSerializeTool` where the true export is `serializeTool`.
 *
 * Run: node --test evals/napi-seam-conformance.mjs
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const NATIVE_SRC = join(REPO_ROOT, 'native', 'src');
const LIB_RS = join(NATIVE_SRC, 'lib.rs');
const NATIVE_EDGE_TS = join(REPO_ROOT, 'src', 'engine', 'retrieval', 'nativeEdge.ts');
const LICENSE_BINDING_TS = join(REPO_ROOT, 'src', 'license', 'binding.ts');

/**
 * The exact free-function NAPI surface of the COMPILED crate, JS name -> arity.
 * Pinned so the scanner cannot silently under-report. Update deliberately when
 * the Rust surface changes; never to make a red eval go green.
 *
 * `encryptCredential`/`decryptCredential` arities updated 3->4 / 4->5 for the
 * CHARIOT-SPEC §12.2 (CH-10) AAD-binding fix: `vault.rs` now takes `adapter_id`
 * on both functions ("AAD = the length-prefixed concatenation LE_u32(len(tenantId_bytes)) ‖ tenantId_bytes ‖ adapterId_bytes",
 * CHARIOT-SPEC.md:1233) so a ciphertext cannot be relocated from one adapter's
 * row to another within the same tenant and still decrypt. This is a
 * deliberate, spec-mandated Rust surface change, not scanner drift — see the
 * CH-10 tests below, which pin the parameter itself (not just its count).
 *
 * `decryptCredential` 5->6 (CHARIOT-SPEC §12.2, CH-10, rulings item 59,
 * 2026-09-04): `vault.rs` now takes a trailing `legacy_allowed: bool` so the
 * CH-10 hard-cutover refusal (unprefixed/legacy ciphertexts refused once a
 * tenant's migration marker exists, `CHARIOT_VAULT_LEGACY_DECRYPT=0`, or
 * enterprise mode without an explicit `CHARIOT_VAULT_LEGACY_DECRYPT=1`
 * override) is enforced in the native layer itself, not only by convention
 * in the TypeScript caller. `vaultProtocolVersion: 0` is a NEW zero-arg
 * capability probe (added by the same change) a caller uses to detect
 * whether a loaded binary is new enough to enforce that gate at all — its
 * absence (a pre-item-59 binary, e.g. the currently signed Sep-1 build)
 * MUST be treated as "legacy refused", never as "legacy allowed", per
 * `src/iam/crypto.ts` `hasVaultLegacyGate()`.
 *
 * `unsealAndVerifySnapshot` 8->9 and `unsealAndVerifySnapshotToFile` 9->10
 * (CHARIOT §5.7, R2 ruling 2026-09-04): the bare `min_epoch: u32` scalar this
 * eval's own doc comment above describes as the original CHARIOT §8.6 fix is
 * ITSELF now removed — `edge_snapshot.rs` no longer accepts a caller-supplied
 * floor at all (CHARIOT::§5.7::31, "The floor SHALL NOT be accepted as a bare
 * scalar from the caller"). Both unseal entry points instead take the signed
 * license JWT (`license_jwt: String`) and verify it themselves
 * (`license.rs::verify_license_jwt_and_extract`), plus `watermark_dir: String`
 * for the persisted anti-rollback epoch watermark (§5.7::34-36). Net: one
 * parameter replaced by two (license_jwt, watermark_dir), so BOTH arities
 * increase by exactly 1 rather than staying flat. `sealEdgeSnapshot: 6` is
 * the new §5.7 producer (`plaintext_b64, secret_root_b64, salt, context,
 * epoch, signing_key_seed_b64`) — the "only encrypt-then-sign producer was a
 * #[cfg(test)] fixture" gap the clause itself called out is now closed.
 *
 * `removeStaleDirValidated: 3` (gate round 4 finding F2, 2026-09-04) is the
 * new descriptor-based, TOCTOU-safe stale-backup remover
 * (`edge_cleanup.rs::remove_stale_dir_validated(parent, name, expected_uid)`)
 * — closes the lstat-then-rmSync TOCTOU gap in `ChariotState.ts`'s prior
 * path-based cleanup. A new module (`native/src/edge_cleanup.rs`), so it
 * also needed a `mod edge_cleanup;` / `pub use edge_cleanup::*;` pair added
 * to `lib.rs` — nothing about `compiledModules()`'s scan changes, it simply
 * now also finds this module.
 *
 * `sealEdgeSnapshotFile: 7` (CHARIOT §5.7 envelope fields, AMENDED
 * 2026-10-14 — `ciphertext` "as a file reference or base64 string"): the
 * file-to-file producer (`plaintext_path, ciphertext_path, secret_root_b64,
 * salt, context, epoch, signing_key_seed_b64`). A real shard archive exceeds
 * V8's maximum string length, so the base64 `sealEdgeSnapshot` cannot carry
 * it; `unsealAndVerifySnapshotToFile` (already pinned at 10) is its consumer
 * and is now declared in nativeEdge.ts too.
 */
const PINNED_EXPORTS = {
  serializeTool: 2,
  serializeQuery: 2,
  frozenSerializerHash: 0,
  discoverInternalApis: 1,
  edgeUnpackSnapshot: 3,
  verifySnapshotSignature: 3,
  unsealAndVerifySnapshot: 9,
  unsealAndVerifySnapshotToFile: 10,
  sealEdgeSnapshot: 6,
  sealEdgeSnapshotFile: 7,
  removeStaleDirValidated: 3,
  validateLicense: 2,
  checkAccess: 4,
  resolveUserAdapters: 3,
  checkAccessForPrincipal: 5,
  resolveUserAdaptersForPrincipal: 4,
  spladePostProcess: 4,
  encryptCredential: 4,
  decryptCredential: 6,
  vaultProtocolVersion: 0,
};

const camel = (s) => s.replace(/_([a-z0-9])/g, (_m, c) => c.toUpperCase());

/** Modules actually compiled into the crate, per `mod X;` in lib.rs. */
function compiledModules() {
  const src = readFileSync(LIB_RS, 'utf-8');
  return [...src.matchAll(/^\s*(?:pub\s+)?mod\s+(\w+)\s*;/gm)].map((m) => m[1]);
}

/** Read from `open` (index of an opening delimiter) to its balanced close. */
function balanced(src, open, oc, cc) {
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    if (src[i] === oc) depth++;
    else if (src[i] === cc) {
      depth--;
      if (depth === 0) return { body: src.slice(open + 1, i), end: i };
    }
  }
  throw new Error(`unbalanced ${oc}${cc} starting at offset ${open}`);
}

/**
 * Every TOP-LEVEL `pub fn` carrying a #[napi...] attribute, as JS name -> params.
 * Column-0 `pub fn` only: impl-block methods are indented and are not part of
 * the free-function seam this eval governs.
 */
function scanNapiFreeFns(file) {
  const src = readFileSync(join(NATIVE_SRC, file), 'utf-8');
  const out = new Map();
  const attr = /#\[(?:napi_derive::)?napi\b/g;
  for (let m = attr.exec(src); m !== null; m = attr.exec(src)) {
    const bracket = src.indexOf('[', m.index);
    const { body: attrBody, end: attrEnd } = balanced(src, bracket, '[', ']');

    // Skip anything between the attribute and the item: doc comments, further
    // attributes, blank lines. Stop at the first non-skippable line.
    let rest = src.slice(attrEnd + 1);
    for (;;) {
      const trimmed = rest.replace(/^[ \t\r\n]*/, '');
      if (trimmed.startsWith('///') || trimmed.startsWith('//') || trimmed.startsWith('#[')) {
        const nl = trimmed.indexOf('\n');
        if (nl === -1) { rest = ''; break; }
        rest = trimmed.slice(nl + 1);
        continue;
      }
      rest = trimmed;
      break;
    }

    // Free functions only: the attribute must sit at column 0 EXACTLY. A
    // `.trim()` test here is wrong — impl-block methods are indented, so a
    // whitespace prefix would trim to '' and let `EdgeShardHandle::load`,
    // `DenseEncoder::load` et al. through, colliding on the bare name `load`.
    const lineStart = src.lastIndexOf('\n', m.index) + 1;
    if (src.slice(lineStart, m.index) !== '') continue;
    if (!rest.startsWith('pub fn ')) continue;

    const sig = /^pub fn\s+([A-Za-z_]\w*)\s*(<[^>]*>)?\s*\(/.exec(rest);
    assert.ok(sig, `unparseable NAPI fn signature after attribute in ${file}: ${rest.slice(0, 90)}`);
    assert.equal(sig[2], undefined, `generic NAPI export in ${file}: ${sig[1]} — scanner cannot bind it`);

    const { body: paramBody } = balanced(rest, rest.indexOf('(', sig[0].length - 1), '(', ')');
    const params = splitTopLevel(paramBody).map((p) => camel(p.split(':')[0].trim()));

    const jsName = /js_name\s*=\s*"([^"]+)"/.exec(attrBody);
    out.set(jsName ? jsName[1] : camel(sig[1]), params);
  }
  return out;
}

/** Split a parameter list on commas that are not nested in <>, (), [] or {}. */
function splitTopLevel(s) {
  const parts = [];
  let depth = 0, cur = '';
  for (const ch of s) {
    if ('<([{'.includes(ch)) depth++;
    else if ('>)]}'.includes(ch)) depth--;
    if (ch === ',' && depth === 0) { parts.push(cur); cur = ''; continue; }
    cur += ch;
  }
  if (cur.trim()) parts.push(cur);
  return parts.map((p) => p.trim()).filter(Boolean);
}

/** Field names of a `#[napi(object)] pub struct <name>`, in order. */
function rustStructFields(file, structName) {
  const src = readFileSync(join(NATIVE_SRC, file), 'utf-8');
  const at = src.indexOf(`pub struct ${structName}`);
  assert.notEqual(at, -1, `Rust struct ${structName} not found in ${file}`);
  const { body } = balanced(src, src.indexOf('{', at), '{', '}');
  return [...body.matchAll(/(?:^|\n)\s*pub\s+(\w+)\s*:/g)].map((f) => camel(f[1]));
}

/** Parameter names of a method declared on a named interface in a TS file. */
function tsInterfaceMethodParams(file, interfaceName, method) {
  const src = readFileSync(file, 'utf-8');
  const declMatch = new RegExp(`(?:^|\\n)(?:export\\s+)?interface\\s+${interfaceName}\\b`).exec(src);
  assert.ok(declMatch, `${interfaceName} interface not found in ${file}`);
  const at = declMatch.index;
  const { body: iface } = balanced(src, src.indexOf('{', at), '{', '}');
  // `\??` accepts an OPTIONAL TS method declaration (`sealEdgeSnapshot?(...)`)
  // — `sealEdgeSnapshot` is declared optional on `NativeEdgeBinding` because
  // it is a producer/tooling seam, not part of the retrieval consumer
  // surface `hasEdgeSurface` requires (same pattern as `SpladeEncoder`/
  // `CrossEncoderScorer`). A REQUIRED method still matches (zero `?`s).
  const decl = new RegExp(`(?:^|\\n)\\s*${method}\\??\\s*\\(`).exec(iface);
  assert.ok(decl, `${interfaceName} does not declare ${method}() — the Rust exports it`);
  const open = iface.indexOf('(', decl.index + decl[0].length - 1);
  const { body } = balanced(iface, open, '(', ')');
  return splitTopLevel(body).map((p) => p.split(':')[0].trim());
}

/** Parameter names of a method declared on the NativeEdgeBinding interface. */
function tsMethodParams(method) {
  return tsInterfaceMethodParams(NATIVE_EDGE_TS, 'NativeEdgeBinding', method);
}

/** Property names of a TS interface in nativeEdge.ts, in order. */
function tsInterfaceFields(name) {
  const src = readFileSync(NATIVE_EDGE_TS, 'utf-8');
  const at = src.indexOf(`export interface ${name}`);
  assert.notEqual(at, -1, `interface ${name} not found`);
  const { body } = balanced(src, src.indexOf('{', at), '{', '}');
  const clean = body.replace(/\/\*\*[\s\S]*?\*\//g, '');
  return [...clean.matchAll(/(?:^|\n)\s*(\w+)\s*\??\s*:/g)].map((f) => f[1]);
}

/** JS name -> params across every COMPILED module. */
function compiledNapiSurface() {
  const all = new Map();
  for (const mod of compiledModules()) {
    const f = `${mod}.rs`;
    if (!existsSync(join(NATIVE_SRC, f))) continue;
    for (const [k, v] of scanNapiFreeFns(f)) {
      assert.ok(!all.has(k), `duplicate NAPI export ${k}`);
      all.set(k, v);
    }
  }
  return all;
}

// ─── anti-bypass: the scanner must see the whole surface ─────────────────────

test('the discovered NAPI export set matches the pinned roster exactly', () => {
  const found = compiledNapiSurface();
  const actual = Object.fromEntries([...found].map(([k, v]) => [k, v.length]));
  assert.deepEqual(
    actual,
    PINNED_EXPORTS,
    'Rust NAPI surface drifted, or the scanner failed to read an export in a form it does not handle. ' +
      'Either way the per-function checks below would compare incomplete maps — fix the scanner or ' +
      'update PINNED_EXPORTS deliberately.',
  );
});

test('js_name overrides are honoured (naive snake->camel is wrong for three exports)', () => {
  const found = compiledNapiSurface();
  for (const name of ['serializeTool', 'serializeQuery', 'frozenSerializerHash']) {
    assert.ok(found.has(name), `${name} must be discovered under its js_name`);
  }
  for (const wrong of ['napiSerializeTool', 'napiSerializeQuery', 'napiFrozenSerializerHash']) {
    assert.ok(!found.has(wrong), `${wrong} means js_name was ignored`);
  }
});

test('orphan modules are excluded — bien_edge/bien_encoder are not in lib.rs', () => {
  const mods = compiledModules();
  for (const orphan of ['bien_edge', 'bien_encoder']) {
    assert.ok(
      !mods.includes(orphan),
      `${orphan} is now declared in lib.rs — it is compiled, so its exports must join PINNED_EXPORTS`,
    );
  }
});

// ─── the sealed-snapshot seam (CHARIOT §5.7 / §8.6) ──────────────────────────────────────

test('unsealAndVerifySnapshot: TS declaration matches the Rust export exactly', () => {
  const rust = compiledNapiSurface().get('unsealAndVerifySnapshot');
  assert.ok(rust, 'edge_snapshot.rs no longer exports unseal_and_verify_snapshot');
  // CHARIOT §5.7, R2 ruling 2026-09-04: the bare min_epoch scalar this eval
  // ONCE required is itself now forbidden (§5.7::31 — "The floor SHALL NOT
  // be accepted as a bare scalar from the caller"). The floor is instead
  // derived in-process from a verified license JWT.
  assert.ok(
    !rust.includes('minEpoch'),
    'CHARIOT §5.7::31: unseal_and_verify_snapshot must NOT take a bare min_epoch scalar — ' +
      'the floor is derived from licenseJwt',
  );
  assert.ok(
    rust.includes('licenseJwt'),
    'CHARIOT §5.7::32/33: unseal_and_verify_snapshot MUST take the signed license JWT and ' +
      'verify it itself',
  );
  assert.ok(
    rust.includes('watermarkDir'),
    'CHARIOT §5.7::34-36: unseal_and_verify_snapshot MUST take the persisted anti-rollback ' +
      'epoch watermark directory',
  );
  assert.deepEqual(
    tsMethodParams('unsealAndVerifySnapshot'),
    rust,
    'sealed-snapshot seam: nativeEdge.ts must declare every parameter the Rust enforces, in order',
  );
});

test('sealEdgeSnapshot: TS declaration matches the Rust export exactly', () => {
  const rust = compiledNapiSurface().get('sealEdgeSnapshot');
  assert.ok(rust, 'edge_snapshot.rs no longer exports seal_edge_snapshot (CHARIOT §5.7 producer)');
  assert.deepEqual(
    tsMethodParams('sealEdgeSnapshot'),
    rust,
    'sealed-snapshot seam (producer): nativeEdge.ts must declare every parameter the Rust ' +
      'enforces, in order — sealEdgeSnapshot is OPTIONAL on the interface (tooling/producer ' +
      'seam, not part of hasEdgeSurface) but its parameter list must still match exactly when present',
  );
});

test('sealEdgeSnapshotFile: TS declaration matches the Rust export exactly', () => {
  const rust = compiledNapiSurface().get('sealEdgeSnapshotFile');
  assert.ok(rust, 'edge_snapshot.rs no longer exports seal_edge_snapshot_file (CHARIOT §5.7 file-reference producer)');
  assert.deepEqual(
    tsMethodParams('sealEdgeSnapshotFile'),
    rust,
    'sealed-snapshot seam (file producer): nativeEdge.ts must declare every parameter the Rust enforces, in order',
  );
});

test('unsealAndVerifySnapshotToFile: TS declaration matches the Rust export exactly', () => {
  const rust = compiledNapiSurface().get('unsealAndVerifySnapshotToFile');
  assert.ok(rust, 'edge_snapshot.rs no longer exports unseal_and_verify_snapshot_to_file');
  assert.ok(!rust.includes('minEpoch'), 'CHARIOT §5.7::31: no bare min_epoch scalar on the file unseal either');
  assert.ok(rust.includes('licenseJwt') && rust.includes('watermarkDir'), 'CHARIOT §5.7::32-36: licence JWT + watermark dir');
  assert.deepEqual(
    tsMethodParams('unsealAndVerifySnapshotToFile'),
    rust,
    'sealed-snapshot seam (file consumer): nativeEdge.ts must declare every parameter the Rust enforces, in order',
  );
});

test('NativeSealedShardFile / NativeUnsealReceipt carry every field the Rust file seal/unseal return', () => {
  assert.deepEqual(tsInterfaceFields('NativeSealedShardFile'), rustStructFields('edge_snapshot.rs', 'SealedShardFile'));
  const receipt = rustStructFields('edge_snapshot.rs', 'UnsealReceipt');
  assert.ok(receipt.includes('receipt'), 'CHARIOT §8.6: UnsealReceipt MUST carry the receipt');
  assert.deepEqual(tsInterfaceFields('NativeUnsealReceipt'), receipt);
});

test('removeStaleDirValidated: TS declaration matches the Rust export exactly', () => {
  const rust = compiledNapiSurface().get('removeStaleDirValidated');
  assert.ok(
    rust,
    'edge_cleanup.rs no longer exports remove_stale_dir_validated (CHARIOT §5.7 gate round 4 F2)',
  );
  assert.deepEqual(
    tsMethodParams('removeStaleDirValidated'),
    rust,
    'sealed-snapshot seam (stale-backup cleanup): nativeEdge.ts must declare every parameter the ' +
      'Rust enforces, in order — removeStaleDirValidated is OPTIONAL on the interface (the runtime ' +
      'binary may not yet be re-signed with this export) but its parameter list must still match ' +
      'exactly when present',
  );
});

test('NativeSealedShard carries every field the Rust sealEdgeSnapshot returns', () => {
  const rust = rustStructFields('edge_snapshot.rs', 'SealedShard');
  assert.deepEqual(
    tsInterfaceFields('NativeSealedShard'),
    rust,
    'CHARIOT §5.7::1-7: the sealedShard descriptor fields TypeScript can observe must match the ' +
      'Rust struct exactly',
  );
});

test('edgeUnpackSnapshot: TS declaration matches the Rust export exactly', () => {
  const rust = compiledNapiSurface().get('edgeUnpackSnapshot');
  assert.ok(rust, 'edge_shard.rs no longer exports edge_unpack_snapshot');
  assert.ok(
    rust.includes('receipt'),
    'CHARIOT §8.6 verify-before-load: edge_unpack_snapshot MUST take the receipt',
  );
  assert.deepEqual(
    tsMethodParams('edgeUnpackSnapshot'),
    rust,
    'sealed-snapshot seam: the verify-before-load gate must be satisfiable from TypeScript',
  );
});

test('verifySnapshotSignature: TS declaration matches the Rust export exactly', () => {
  const rust = compiledNapiSurface().get('verifySnapshotSignature');
  assert.ok(rust, 'edge_snapshot.rs no longer exports verify_snapshot_signature');
  assert.deepEqual(tsMethodParams('verifySnapshotSignature'), rust);
});

test('NativeUnsealedSnapshot carries every field the Rust returns', () => {
  const rust = rustStructFields('edge_snapshot.rs', 'UnsealedSnapshot');
  assert.ok(rust.includes('receipt'), 'CHARIOT §8.6: UnsealedSnapshot MUST carry the receipt');
  assert.deepEqual(
    tsInterfaceFields('NativeUnsealedSnapshot'),
    rust,
    'sealed-snapshot seam: omitting `receipt` made the chain of custody unrepresentable in TS',
  );
});

// ─── the credential-vault seam (CHARIOT-SPEC §12.2, CH-10) ───────────────────

test('encryptCredential: TS declaration matches the Rust export exactly', () => {
  const rust = compiledNapiSurface().get('encryptCredential');
  assert.ok(rust, 'vault.rs no longer exports encrypt_credential');
  assert.ok(
    rust.includes('adapterId'),
    'CHARIOT §12.2 (CH-10): encrypt_credential MUST take adapter_id — ' +
      '"AAD = the length-prefixed concatenation LE_u32(len(tenantId_bytes)) ‖ tenantId_bytes ‖ adapterId_bytes" (CHARIOT-SPEC.md:1233)',
  );
  assert.deepEqual(
    tsInterfaceMethodParams(LICENSE_BINDING_TS, 'NativeBinding', 'encryptCredential'),
    rust,
    'CH-10: src/license/binding.ts must declare every parameter the Rust ' +
      'enforces, in order, or the AAD binding is unpassable from TypeScript',
  );
});

test('decryptCredential: TS declaration matches the Rust export exactly', () => {
  const rust = compiledNapiSurface().get('decryptCredential');
  assert.ok(rust, 'vault.rs no longer exports decrypt_credential');
  assert.ok(
    rust.includes('adapterId'),
    'CHARIOT §12.2 (CH-10): decrypt_credential MUST take adapter_id — ' +
      'a relocated ciphertext must fail the AAD check, not silently decrypt',
  );
  assert.ok(
    rust.includes('legacyAllowed'),
    'CHARIOT §12.2 (CH-10, rulings item 59): decrypt_credential MUST take ' +
      'legacy_allowed — the hard-cutover refusal must be enforceable at the ' +
      'native layer, not only by TypeScript-side convention',
  );
  assert.deepEqual(
    tsInterfaceMethodParams(LICENSE_BINDING_TS, 'NativeBinding', 'decryptCredential'),
    rust,
    'CH-10: src/license/binding.ts must declare every parameter the Rust ' +
      'enforces, in order, or the anti-relocation check is unpassable from TypeScript',
  );
});

test('vaultProtocolVersion: capability probe is a zero-arg export', () => {
  const rust = compiledNapiSurface().get('vaultProtocolVersion');
  assert.ok(
    rust,
    'vault.rs no longer exports vault_protocol_version — rulings item 59 ' +
      'requires this probe so callers can detect whether a loaded binary ' +
      'enforces the CH-10 legacy-ciphertext gate before trusting it',
  );
  assert.deepEqual(rust, [], 'vaultProtocolVersion takes no parameters');
});

// ─── the comparison itself must be able to fail ──────────────────────────────

test('anti-vacuous: a dropped trailing parameter is caught', () => {
  const rust = compiledNapiSurface().get('unsealAndVerifySnapshot');
  const preFix = rust.slice(0, -1); // exactly the pre-fix (receipt-less) shape
  assert.equal(preFix.length, rust.length - 1);
  assert.throws(() => assert.deepEqual(preFix, rust));
});

test('anti-vacuous: the balanced scanner survives a type containing a comma and parens', () => {
  const parts = splitTopLevel('a: Option<Vec<(u32, f64)>>, b: String, c: HashMap<String, u8>');
  assert.deepEqual(parts.map((p) => p.split(':')[0].trim()), ['a', 'b', 'c']);
});
