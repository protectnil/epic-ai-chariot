/**
 * Offline kit installer (dogfood-ready 4.0 contract) — tests derived from the
 * failure classes of the contract clause "verify every sha256 first (any
 * mismatch or path traversal → abort with an actionable error, install
 * nothing), copy into the Epic AI dir (0600 files / 0700 dirs), install the
 * licence via the existing activateLicenseFromPath … Idempotent on re-run":
 *   absent kit · happy path · hash mismatch installs nothing · traversal /
 *   absolute / backslash / out-of-layout paths · unlisted file · listed file
 *   missing · symlink (file, directory, kit root) · malformed manifest
 *   (missing / not JSON / version / empty / bad hash / case collision) ·
 *   idempotent re-run · corrupted destination replaced · destination is a
 *   directory · licence routed through activate (refusal installs nothing;
 *   same licence skipped; newer installed licence kept; older replaced).
 *
 * The licence step is driven through injected deps — no real signing key,
 * no write to the real ~/.epic-ai.
 *
 * Run (after tsc): node --test dist/cli/offline-kit.test.js
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

const root = mkdtempSync(join(tmpdir(), 'chariot-offline-kit-'));
// Defence in depth: any accidental default-deps path lands in the sandbox.
process.env.HOME = root;
process.env.EPIC_AI_DIR_OVERRIDE = join(root, 'override-home');

const {
  installOfflineKit,
  validateKitRelPath,
  formatOfflineKitSummary,
} = await import('./offline-kit.js');
const { ChariotError } = await import('./envelope.js');
type Deps = import('./offline-kit.js').OfflineKitDeps;
type Outcome = import('../license/activate.js').ActivateOutcome;

after(() => rmSync(root, { recursive: true, force: true }));

let caseNo = 0;
function sha(b: string | Buffer): string {
  return createHash('sha256').update(b).digest('hex');
}

const KIT_LICENSE = JSON.stringify({ jwt: 'h.kit.s', renewal_secret: 'r', seal_secret: 'A'.repeat(43) + '=' });

const BASE_FILES: Record<string, string> = {
  'models/dense/model.onnx': 'dense-onnx-bytes',
  'models/dense/tokenizer.json': '{"t":1}',
  'models/splade/model.onnx': 'splade-onnx-bytes',
  'models/reranker/model.onnx': 'reranker-onnx-bytes',
  'models/reranker/config.json': '{"max_position_embeddings":512}',
  'edgeshard/catalog.edgeshard.sealed': '{"ciphertext":{"file":"catalog.edgeshard.sealed.ciphertext","sha256":"x"}}',
  'edgeshard/catalog.edgeshard.sealed.ciphertext': 'sealed-ciphertext-bytes',
  'lib/libonnxruntime.so': 'ort-so',
  'lib/libonnxruntime.so.1': 'ort-so',
  'chariot.license': KIT_LICENSE,
};

interface Fixture {
  pkg: string;
  kit: string;
  home: string;
  licensePath: string;
  calls: string[];
  deps: Deps;
}

/**
 * Build a package root with kit/ + manifest. `manifestFiles` overrides the
 * hash map written to the manifest (default: the true hashes of `files`).
 */
function fixture(opts: {
  files?: Record<string, string>;
  manifestFiles?: Record<string, unknown>;
  manifest?: unknown;
  activate?: (src: string, licensePath: string) => Outcome;
  verifyJwt?: Deps['verifyJwt'];
} = {}): Fixture {
  const dir = join(root, `case-${++caseNo}`);
  const pkg = join(dir, 'pkg');
  const kit = join(pkg, 'kit');
  const home = join(dir, 'epic-ai');
  const licensePath = join(dir, 'licence-home', 'chariot.license');
  mkdirSync(kit, { recursive: true });
  const files = opts.files ?? BASE_FILES;
  const hashes: Record<string, string> = {};
  for (const [rel, body] of Object.entries(files)) {
    const p = join(kit, ...rel.split('/'));
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, body);
    hashes[rel] = sha(body);
  }
  const manifest = opts.manifest ?? { version: 1, files: opts.manifestFiles ?? hashes };
  writeFileSync(join(kit, 'kit-manifest.json'), typeof manifest === 'string' ? manifest : JSON.stringify(manifest));
  const calls: string[] = [];
  const activate = opts.activate ?? ((src: string, dest: string): Outcome => {
    mkdirSync(dirname(dest), { recursive: true });
    copyFileSync(src, dest);
    return {
      ok: true,
      claims: { companyId: 'acme', expiresAtIso: '2027-01-01T00:00:00.000Z', expUnix: 1798761600, issuedAtIso: '2026-01-01T00:00:00.000Z', iss: 'test', licenseEpoch: 1, minSecurityEpoch: 0 },
      writtenPath: dest,
    };
  });
  const deps: Deps = {
    activateLicense: (src) => { calls.push(src); return activate(src, licensePath); },
    installedLicensePath: licensePath,
    verifyJwt: opts.verifyJwt ?? (() => null),
  };
  return { pkg, kit, home, licensePath, calls, deps };
}

async function expectKitError(p: Promise<unknown>, code: string, causeRe?: RegExp): Promise<void> {
  await assert.rejects(p, (err: unknown) => {
    assert.ok(err instanceof ChariotError, `expected ChariotError, got ${String(err)}`);
    assert.equal(err.envelope.code, code);
    assert.equal(err.envelope.surface, 'cli:wizard');
    assert.ok((err.envelope.remediation ?? []).length > 0, 'remediation present');
    if (causeRe) assert.match(err.envelope.cause ?? '', causeRe);
    return true;
  });
}

function nothingInstalled(f: Fixture): void {
  assert.equal(existsSync(f.home) ? readdirSync(f.home).length : 0, 0, 'Epic AI dir must stay empty');
  assert.equal(existsSync(f.licensePath), false, 'licence must not be installed');
}

const POSIX = process.platform !== 'win32';

// ── absent ────────────────────────────────────────────────────────────────

test('absent kit/: present=false, nothing written, no output lines', async () => {
  const dir = join(root, `case-${++caseNo}`);
  mkdirSync(join(dir, 'pkg'), { recursive: true });
  const home = join(dir, 'epic-ai');
  let called = false;
  const r = await installOfflineKit(join(dir, 'pkg'), home, {
    activateLicense: () => { called = true; throw new Error('unreachable'); },
    installedLicensePath: join(dir, 'l'),
    verifyJwt: () => null,
  });
  assert.deepEqual(r, { present: false });
  assert.equal(existsSync(home), false);
  assert.equal(called, false);
  assert.deepEqual(formatOfflineKitSummary(r), []);
});

// ── happy path ────────────────────────────────────────────────────────────

test('happy path: every file mirrored, 0600 files / 0700 created dirs, licence via activate only', async () => {
  const f = fixture();
  const r = await installOfflineKit(f.pkg, f.home, f.deps);
  assert.equal(r.present, true);
  if (!r.present) return;
  for (const [rel, body] of Object.entries(BASE_FILES)) {
    if (rel === 'chariot.license') continue;
    const dest = join(f.home, ...rel.split('/'));
    assert.equal(readFileSync(dest, 'utf-8'), body, rel);
    if (POSIX) assert.equal(statSync(dest).mode & 0o777, 0o600, `${rel} mode`);
  }
  if (POSIX) {
    for (const d of ['', 'models', 'models/dense', 'models/splade', 'models/reranker', 'edgeshard', 'lib']) {
      assert.equal(statSync(join(f.home, ...d.split('/').filter(Boolean))).mode & 0o777, 0o700, `dir ${d || '.'} mode`);
    }
  }
  // Licence: routed through activate with the re-hashed STAGED copy of the
  // kit licence, staged OUTSIDE the Epic AI dir; never copied raw into it.
  assert.equal(f.calls.length, 1);
  assert.match(f.calls[0]!, /\/chariot-kit-licence-[^/]+\/license$/);
  assert.ok(!f.calls[0]!.startsWith(f.home), 'licence staging is outside the Epic AI dir');
  assert.equal(existsSync(f.calls[0]!), false, 'licence staging copy removed');
  assert.equal(readdirSync(f.home).some(n => n.startsWith('.kit-staging-')), false, 'staging directory removed');
  assert.equal(existsSync(join(f.home, 'chariot.license')), false);
  assert.equal(r.license.kind, 'activated');
  assert.deepEqual(
    r.classes.map(c => [c.cls, c.installed, c.unchanged]),
    [['models', 5, 0], ['edgeshard', 2, 0], ['onnxruntime', 2, 0]],
  );
  // No tmp residue.
  const residue: string[] = [];
  const walk = (d: string): void => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      if (e.isDirectory()) walk(join(d, e.name));
      else if (e.name.includes('.kit-tmp.')) residue.push(e.name);
    }
  };
  walk(f.home);
  assert.deepEqual(residue, []);
  assert.deepEqual(formatOfflineKitSummary(r), [
    'Offline kit: licence activated for acme (expires 2027-01-01T00:00:00.000Z)',
    'Offline kit: retrieval models installed (5 files, 5 written)',
    'Offline kit: sealed catalog shard installed (2 files, 2 written)',
    'Offline kit: ONNX Runtime library installed (2 files, 2 written)',
  ]);
});

test('licence is optional: a kit without chariot.license installs files, never calls activate', async () => {
  const files = { ...BASE_FILES };
  delete files['chariot.license'];
  const f = fixture({ files });
  const r = await installOfflineKit(f.pkg, f.home, f.deps);
  assert.ok(r.present);
  if (!r.present) return;
  assert.equal(r.license.kind, 'absent');
  assert.deepEqual(f.calls, []);
});

// ── hash mismatch ─────────────────────────────────────────────────────────

test('hash mismatch on the LAST entry installs nothing (no file, no licence)', async () => {
  const hashes: Record<string, string> = {};
  for (const [rel, body] of Object.entries(BASE_FILES)) hashes[rel] = sha(body);
  hashes['lib/libonnxruntime.so.1'] = sha('different bytes');
  const f = fixture({ manifestFiles: hashes });
  await expectKitError(installOfflineKit(f.pkg, f.home, f.deps), 'OFFLINE_KIT_INVALID', /libonnxruntime\.so\.1 sha256/);
  nothingInstalled(f);
  assert.deepEqual(f.calls, []);
});

test('hash mismatch on the licence installs nothing', async () => {
  const hashes: Record<string, string> = {};
  for (const [rel, body] of Object.entries(BASE_FILES)) hashes[rel] = sha(body);
  hashes['chariot.license'] = sha('tampered');
  const f = fixture({ manifestFiles: hashes });
  await expectKitError(installOfflineKit(f.pkg, f.home, f.deps), 'OFFLINE_KIT_INVALID', /chariot\.license/);
  nothingInstalled(f);
  assert.deepEqual(f.calls, []);
});

test('uppercase manifest hashes are accepted (case-insensitive hex)', async () => {
  const hashes: Record<string, string> = {};
  for (const [rel, body] of Object.entries(BASE_FILES)) hashes[rel] = sha(body).toUpperCase();
  const f = fixture({ manifestFiles: hashes });
  const r = await installOfflineKit(f.pkg, f.home, f.deps);
  assert.equal(r.present, true);
});

// ── path validation ───────────────────────────────────────────────────────

test('validateKitRelPath rejects traversal, absolute, backslash, empty segments and out-of-layout paths', () => {
  const bad = [
    '', '../evil', 'models/../../x', 'models/./x', './models/x', 'models//x', 'models/x/',
    '/etc/passwd', '/models/x', 'C:/x', 'c:x', 'models\\x', '\\\\server\\share', 'models/\0x',
    'kit-manifest.json', '.env', 'config.json', 'adapter-state.json', 'models', 'lib', 'edgeshard',
    'other/x', 'chariot.license/x', 'Models/x',
    // §17.2a exact layout: nothing else under models/, edgeshard/ or lib/.
    'models/manifest.json', 'models/x', 'models/other/model.onnx', 'models/dense/sub/model.onnx',
    'edgeshard/other.bin', 'edgeshard/catalog.edgeshard.sealed/x', 'lib/arbitrary-file',
    // Only the exact file-form ciphertext name beside the descriptor (CHARIOT §5.7).
    'edgeshard/catalog.edgeshard.sealed.ciphertext/x', 'edgeshard/other.ciphertext',
    'edgeshard/catalog.edgeshard.sealed.ciphertext.bak', 'edgeshard/catalog.edgeshard.sealed.Ciphertext',
    'edgeshard/sub/catalog.edgeshard.sealed.ciphertext', 'catalog.edgeshard.sealed.ciphertext',
    'models/dense/../../edgeshard/catalog.edgeshard.sealed.ciphertext',
    'lib/libonnxruntime.so.x', 'lib/sub/libonnxruntime.so', 'lib/libonnxruntime.dylib',
  ];
  for (const rel of bad) {
    assert.equal(validateKitRelPath(rel).ok, false, JSON.stringify(rel));
  }
  const good: Array<[string, string]> = [
    ['models/dense/model.onnx', 'models'],
    ['models/reranker/tokenizer_config.json', 'models'],
    ['models/splade/model.onnx', 'models'],
    ['edgeshard/catalog.edgeshard.sealed', 'edgeshard'],
    ['edgeshard/catalog.edgeshard.sealed.ciphertext', 'edgeshard'],
    ['lib/libonnxruntime.so', 'onnxruntime'],
    ['lib/libonnxruntime.so.1', 'onnxruntime'],
    ['lib/libonnxruntime.so.1.24.4', 'onnxruntime'],
    ['chariot.license', 'license'],
  ];
  for (const [rel, cls] of good) {
    const v = validateKitRelPath(rel);
    assert.ok(v.ok, rel);
    if (v.ok) assert.equal(v.cls, cls);
  }
});

test('manifest entry with ../ traversal is refused before anything is written', async () => {
  const f = fixture({ manifestFiles: { ...Object.fromEntries(Object.entries(BASE_FILES).map(([k, v]) => [k, sha(v)])), '../outside': sha('x') } });
  await expectKitError(installOfflineKit(f.pkg, f.home, f.deps), 'OFFLINE_KIT_INVALID', /illegal path segment/);
  nothingInstalled(f);
  assert.deepEqual(f.calls, []);
});

test('manifest entry with an absolute path is refused', async () => {
  const f = fixture({ manifestFiles: { '/etc/passwd': sha('x') } });
  await expectKitError(installOfflineKit(f.pkg, f.home, f.deps), 'OFFLINE_KIT_INVALID', /absolute path/);
  nothingInstalled(f);
});

test('manifest entry outside the layout (.env) is refused', async () => {
  const f = fixture({ files: { '.env': 'K=V' } });
  await expectKitError(installOfflineKit(f.pkg, f.home, f.deps), 'OFFLINE_KIT_INVALID', /outside the kit layout/);
  nothingInstalled(f);
});

// ── tree checks ───────────────────────────────────────────────────────────

test('unlisted file in kit/ is refused and nothing is installed', async () => {
  const f = fixture();
  writeFileSync(join(f.kit, 'models', 'dense', 'extra.bin'), 'x');
  await expectKitError(installOfflineKit(f.pkg, f.home, f.deps), 'OFFLINE_KIT_INVALID', /extra\.bin is not listed/);
  nothingInstalled(f);
  assert.deepEqual(f.calls, []);
});

test('listed file missing from kit/ is refused and nothing is installed', async () => {
  const hashes: Record<string, string> = {};
  for (const [rel, body] of Object.entries(BASE_FILES)) hashes[rel] = sha(body);
  hashes['models/splade/tokenizer.json'] = sha('{}');
  const f = fixture({ manifestFiles: hashes });
  await expectKitError(installOfflineKit(f.pkg, f.home, f.deps), 'OFFLINE_KIT_INVALID', /splade\/tokenizer\.json is listed .* but missing/);
  nothingInstalled(f);
});

test('symlinked file inside kit/ is refused (even when listed with the target hash)', { skip: !POSIX }, async () => {
  const outside = join(root, `secret-${caseNo}`);
  writeFileSync(outside, 'secret');
  const files = { ...BASE_FILES };
  const f = fixture({ files });
  const link = join(f.kit, 'edgeshard', 'catalog.edgeshard.sealed');
  rmSync(link);
  symlinkSync(outside, link);
  const m = JSON.parse(readFileSync(join(f.kit, 'kit-manifest.json'), 'utf-8')) as { files: Record<string, string> };
  m.files['edgeshard/catalog.edgeshard.sealed'] = sha('secret');
  writeFileSync(join(f.kit, 'kit-manifest.json'), JSON.stringify({ version: 1, files: m.files }));
  await expectKitError(installOfflineKit(f.pkg, f.home, f.deps), 'OFFLINE_KIT_INVALID', /symbolic link/);
  nothingInstalled(f);
});

test('symlinked directory inside kit/ is refused', { skip: !POSIX }, async () => {
  const f = fixture();
  const elsewhere = join(root, `elsewhere-${caseNo}`);
  mkdirSync(elsewhere, { recursive: true });
  symlinkSync(elsewhere, join(f.kit, 'models', 'linked'));
  await expectKitError(installOfflineKit(f.pkg, f.home, f.deps), 'OFFLINE_KIT_INVALID', /symbolic link/);
  nothingInstalled(f);
});

test('kit/ itself being a symlink is refused', { skip: !POSIX }, async () => {
  const f = fixture();
  const real = join(dirname(f.pkg), 'real-kit');
  // Move the real kit aside and point kit/ at it.
  mkdirSync(real);
  for (const e of readdirSync(f.kit)) {
    copyTree(join(f.kit, e), join(real, e));
  }
  rmSync(f.kit, { recursive: true });
  symlinkSync(real, f.kit);
  await expectKitError(installOfflineKit(f.pkg, f.home, f.deps), 'OFFLINE_KIT_INVALID', /not a directory/);
  nothingInstalled(f);
});

function copyTree(src: string, dest: string): void {
  if (statSync(src).isDirectory()) {
    mkdirSync(dest, { recursive: true });
    for (const e of readdirSync(src)) copyTree(join(src, e), join(dest, e));
  } else {
    copyFileSync(src, dest);
  }
}

// ── manifest shape ────────────────────────────────────────────────────────

test('malformed manifests are refused with OFFLINE_KIT_INVALID and install nothing', async () => {
  const goodHashes = Object.fromEntries(Object.entries(BASE_FILES).map(([k, v]) => [k, sha(v)]));
  const cases: Array<[unknown, RegExp]> = [
    ['{not json', /not valid JSON/],
    [[], /not a JSON object/],
    [null, /not a JSON object/],
    [{ version: 2, files: goodHashes }, /unsupported version 2/],
    [{ version: '1', files: goodHashes }, /unsupported version/],
    [{ files: goodHashes }, /unsupported version/],
    [{ version: 1 }, /no "files" object/],
    [{ version: 1, files: [] }, /no "files" object/],
    [{ version: 1, files: {} }, /lists no files/],
    [{ version: 1, files: { ...goodHashes, 'models/dense/config.json': 'abc' } }, /64-hex-digit sha256/],
    [{ version: 1, files: { ...goodHashes, 'models/dense/config.json': 42 } }, /64-hex-digit sha256/],
  ];
  for (const [manifest, re] of cases) {
    const f = fixture({ manifest: typeof manifest === 'string' ? manifest : JSON.stringify(manifest) });
    await expectKitError(installOfflineKit(f.pkg, f.home, f.deps), 'OFFLINE_KIT_INVALID', re);
    nothingInstalled(f);
    assert.deepEqual(f.calls, []);
  }
});

test('missing kit-manifest.json is refused', async () => {
  const f = fixture();
  rmSync(join(f.kit, 'kit-manifest.json'));
  await expectKitError(installOfflineKit(f.pkg, f.home, f.deps), 'OFFLINE_KIT_INVALID', /kit-manifest\.json is missing/);
  nothingInstalled(f);
});

test('case-colliding manifest keys are refused', async () => {
  const f = fixture({ files: { 'models/dense/a.bin': 'x' }, manifestFiles: { 'models/dense/a.bin': sha('x'), 'models/dense/A.bin': sha('x') } });
  await expectKitError(installOfflineKit(f.pkg, f.home, f.deps), 'OFFLINE_KIT_INVALID', /collide/);
  nothingInstalled(f);
});

// ── idempotency / destination state ───────────────────────────────────────

test('idempotent re-run: same hashes skip every file and the same licence', async () => {
  const f = fixture();
  await installOfflineKit(f.pkg, f.home, f.deps);
  const before = statSync(join(f.home, 'models', 'dense', 'model.onnx')).mtimeMs;
  const ctimeBefore = statSync(join(f.home, 'edgeshard', 'catalog.edgeshard.sealed')).ctimeMs;
  const r = await installOfflineKit(f.pkg, f.home, f.deps);
  // §17.2a::26: a re-run changes no file — not even its metadata.
  assert.equal(statSync(join(f.home, 'edgeshard', 'catalog.edgeshard.sealed')).ctimeMs, ctimeBefore);
  assert.ok(r.present);
  if (!r.present) return;
  assert.deepEqual(
    r.classes.map(c => [c.cls, c.installed, c.unchanged]),
    [['models', 0, 5], ['edgeshard', 0, 2], ['onnxruntime', 0, 2]],
  );
  assert.equal(r.license.kind, 'unchanged');
  assert.equal(f.calls.length, 1, 'activate ran on the first run only');
  assert.equal(statSync(join(f.home, 'models', 'dense', 'model.onnx')).mtimeMs, before);
  assert.deepEqual(formatOfflineKitSummary(r), [
    'Offline kit: licence already installed',
    'Offline kit: retrieval models already installed (5 files)',
    'Offline kit: sealed catalog shard already installed (2 files)',
    'Offline kit: ONNX Runtime library already installed (2 files)',
  ]);
});

test('an unchanged destination with a loose mode is tightened to 0600 on re-run (§17.2a)', { skip: !POSIX }, async () => {
  const f = fixture();
  await installOfflineKit(f.pkg, f.home, f.deps);
  const dest = join(f.home, 'models', 'dense', 'model.onnx');
  chmodSync(dest, 0o644);
  const r = await installOfflineKit(f.pkg, f.home, f.deps);
  assert.ok(r.present);
  assert.equal(statSync(dest).mode & 0o777, 0o600);
});

test('a corrupted destination file is replaced on re-run', async () => {
  const f = fixture();
  await installOfflineKit(f.pkg, f.home, f.deps);
  const dest = join(f.home, 'edgeshard', 'catalog.edgeshard.sealed');
  writeFileSync(dest, 'corrupt');
  const r = await installOfflineKit(f.pkg, f.home, f.deps);
  assert.ok(r.present);
  if (!r.present) return;
  assert.equal(readFileSync(dest, 'utf-8'), BASE_FILES['edgeshard/catalog.edgeshard.sealed']);
  // Only the corrupted descriptor is rewritten; its untouched ciphertext sibling is skipped.
  assert.deepEqual(r.classes.find(c => c.cls === 'edgeshard'), { cls: 'edgeshard', installed: 1, unchanged: 1 });
});

test('pre-existing Epic AI dir permissions are not altered; new subdirs are 0700', { skip: !POSIX }, async () => {
  const f = fixture();
  mkdirSync(join(f.home, 'models'), { recursive: true, mode: 0o755 });
  chmodSync(join(f.home, 'models'), 0o755);
  await installOfflineKit(f.pkg, f.home, f.deps);
  assert.equal(statSync(join(f.home, 'models')).mode & 0o777, 0o755);
  assert.equal(statSync(join(f.home, 'models', 'dense')).mode & 0o777, 0o700);
});

test('destination path occupied by a directory → OFFLINE_KIT_INSTALL_FAILED', async () => {
  const f = fixture({ files: { 'edgeshard/catalog.edgeshard.sealed': 'x' } });
  mkdirSync(join(f.home, 'edgeshard', 'catalog.edgeshard.sealed'), { recursive: true });
  await expectKitError(installOfflineKit(f.pkg, f.home, f.deps), 'OFFLINE_KIT_INSTALL_FAILED', /is a directory/);
});

// ── licence routing ───────────────────────────────────────────────────────

test('licence refused by activate → OFFLINE_KIT_LICENSE_REJECTED, no model/shard/runtime byte written', async () => {
  const f = fixture({
    activate: () => ({ ok: false, reason: 'expired', message: 'License expired at 2020-01-01T00:00:00.000Z.' }),
  });
  await expectKitError(installOfflineKit(f.pkg, f.home, f.deps), 'OFFLINE_KIT_LICENSE_REJECTED', /\(expired\)/);
  nothingInstalled(f);
  assert.equal(f.calls.length, 1);
});

test('installed licence for the same company expiring LATER is kept (no downgrade on re-run)', async () => {
  const f = fixture({
    verifyJwt: (jwt) => jwt === 'h.renewed.s' ? { companyId: 'acme', expUnix: 2_000_000_000 } : { companyId: 'acme', expUnix: 1_900_000_000 },
  });
  mkdirSync(dirname(f.licensePath), { recursive: true });
  const installed = JSON.stringify({ jwt: 'h.renewed.s', renewal_secret: 'r', seal_secret: 'A'.repeat(43) + '=' });
  writeFileSync(f.licensePath, installed);
  const r = await installOfflineKit(f.pkg, f.home, f.deps);
  assert.ok(r.present);
  if (!r.present) return;
  assert.equal(r.license.kind, 'kept-newer');
  assert.deepEqual(f.calls, []);
  assert.equal(readFileSync(f.licensePath, 'utf-8'), installed);
});

test('installed licence that is older, another company, or unverifiable is replaced via activate', async () => {
  const variants: Array<Deps['verifyJwt']> = [
    (jwt) => jwt === 'h.kit.s' ? { companyId: 'acme', expUnix: 2_000_000_000 } : { companyId: 'acme', expUnix: 1_000_000_000 },
    (jwt) => jwt === 'h.kit.s' ? { companyId: 'acme', expUnix: 1_000_000_000 } : { companyId: 'other', expUnix: 2_000_000_000 },
    (jwt) => jwt === 'h.kit.s' ? { companyId: 'acme', expUnix: 1_000_000_000 } : null,
    (jwt) => jwt === 'h.kit.s' ? { companyId: 'acme', expUnix: 1_000_000_000 } : { companyId: 'acme', expUnix: 1_000_000_000 },
  ];
  for (const verifyJwt of variants) {
    const f = fixture({ verifyJwt });
    mkdirSync(dirname(f.licensePath), { recursive: true });
    writeFileSync(f.licensePath, JSON.stringify({ jwt: 'h.installed.s', renewal_secret: 'r' }));
    const r = await installOfflineKit(f.pkg, f.home, f.deps);
    assert.ok(r.present);
    if (!r.present) return;
    assert.equal(r.license.kind, 'activated');
    assert.equal(f.calls.length, 1);
    assert.match(f.calls[0]!, /\/chariot-kit-licence-[^/]+\/license$/);
  }
});

test('same JWT but the installed envelope lacks seal_secret → re-activated (not treated as unchanged)', async () => {
  const f = fixture();
  mkdirSync(dirname(f.licensePath), { recursive: true });
  writeFileSync(f.licensePath, JSON.stringify({ jwt: 'h.kit.s', renewal_secret: 'r' }));
  const r = await installOfflineKit(f.pkg, f.home, f.deps);
  assert.ok(r.present);
  if (!r.present) return;
  assert.equal(r.license.kind, 'activated');
  assert.equal(f.calls.length, 1);
});
