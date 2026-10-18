/**
 * CHARIOT::§5.7 — sealed-shard operator configuration (`sealedShardConfig.ts`).
 *
 * `process.env.HOME` is redirected to a sandbox for every test — Node's
 * `os.homedir()` reads `$HOME` on POSIX first (before falling back to a
 * passwd lookup), and `src/license/loader.ts::getLicensePath()` is built on
 * `homedir()` with no override mechanism of its own, so this is the only
 * safe way to control where `readLicenseEnvelope()` looks without touching
 * the real `~/.epic-ai/chariot.license` (which may hold a REAL license on
 * the machine running this suite).
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// master-key reference: VALIDATION ONLY (format/presence check, no derivation or encrypt/decrypt call)

const realHome = process.env.HOME;

// `src/cli/paths.ts::EPIC_AI_DIR` is fixed at module load, and the sealed
// descriptor DEFAULT (`<EPIC_AI_DIR>/edgeshard/catalog.edgeshard.sealed`)
// hangs off it — point it at an empty sandbox BEFORE the import so a real
// `~/.epic-ai/edgeshard/` on the host can never change these verdicts.
const epicAiDirSandbox = mkdtempSync(join(tmpdir(), 'chariot-sealed-shard-epic-dir-'));
process.env.EPIC_AI_DIR_OVERRIDE = epicAiDirSandbox;

const {
  loadSealedShardDescriptor,
  resolveSealedShardDescriptorPath,
  defaultSealedShardDescriptorPath,
  SEALED_SHARD_DESCRIPTOR_ENV,
} = await import('./sealedShardConfig.js');

function freshHomeSandbox(): string {
  const home = mkdtempSync(join(tmpdir(), 'chariot-sealed-shard-home-'));
  process.env.HOME = home;
  return home;
}

function writeLicenseEnvelope(home: string, jwt: string): void {
  const dir = join(home, '.epic-ai');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'chariot.license'), JSON.stringify({ jwt, renewal_secret: 'unused-in-this-test' }));
}

function clearEnv(): void {
  delete process.env[SEALED_SHARD_DESCRIPTOR_ENV];
  delete process.env.ENTERPRISE_MASTER_KEY;
}

function writeDescriptor(path: string, body: unknown): void {
  writeFileSync(path, JSON.stringify(body));
}

test('descriptor env var unset → returns null (the expected "not configured" state)', () => {
  clearEnv();
  assert.equal(loadSealedShardDescriptor(), null);
});

test('descriptor path configured but file missing → null (fail closed, not "absent")', () => {
  clearEnv();
  const home = freshHomeSandbox();
  process.env[SEALED_SHARD_DESCRIPTOR_ENV] = join(home, 'does-not-exist.json');
  assert.equal(loadSealedShardDescriptor(), null);
});

test('descriptor file present but malformed JSON → null', () => {
  clearEnv();
  const home = freshHomeSandbox();
  const p = join(home, 'malformed.json');
  writeFileSync(p, 'not json');
  process.env[SEALED_SHARD_DESCRIPTOR_ENV] = p;
  assert.equal(loadSealedShardDescriptor(), null);
});

test('descriptor file present but missing a required field → null', () => {
  clearEnv();
  const home = freshHomeSandbox();
  const p = join(home, 'incomplete.json');
  writeDescriptor(p, { ciphertextB64: 'eA==', ivB64: 'y', signatureB64: 'z', salt: 'tenant-x' }); // no aad
  process.env[SEALED_SHARD_DESCRIPTOR_ENV] = p;
  assert.equal(loadSealedShardDescriptor(), null);
});

test('valid descriptor but no license envelope on disk → null', () => {
  clearEnv();
  const home = freshHomeSandbox(); // no chariot.license written
  const p = join(home, 'valid.json');
  writeDescriptor(p, {
    ciphertextB64: 'eA==',
    ivB64: 'y',
    signatureB64: 'z',
    salt: 'tenant-x',
    aad: 'tenant-x|epoch=1',
  });
  process.env[SEALED_SHARD_DESCRIPTOR_ENV] = p;
  process.env.ENTERPRISE_MASTER_KEY = Buffer.alloc(32, 7).toString('base64');
  assert.equal(loadSealedShardDescriptor(), null);
});

test('valid descriptor + license envelope but ENTERPRISE_MASTER_KEY unset → null', () => {
  clearEnv();
  const home = freshHomeSandbox();
  writeLicenseEnvelope(home, 'header.payload.signature');
  const descriptorPath = join(home, 'valid2.json');
  writeDescriptor(descriptorPath, {
    ciphertextB64: 'eA==',
    ivB64: 'y',
    signatureB64: 'z',
    salt: 'tenant-x',
    aad: 'tenant-x|epoch=1',
  });
  process.env[SEALED_SHARD_DESCRIPTOR_ENV] = descriptorPath;
  assert.equal(loadSealedShardDescriptor(), null);
});

test('fully configured → resolves the complete SealedShardConfig, licenseJwt from the loader envelope', () => {
  clearEnv();
  const home = freshHomeSandbox();
  writeLicenseEnvelope(home, 'fake-header.fake-payload.fake-signature');
  const descriptorPath = join(home, 'valid3.json');
  writeDescriptor(descriptorPath, {
    ciphertextB64: 'Q0lQSEVSVEVYVA==',
    ivB64: 'IV',
    signatureB64: 'SIG',
    salt: 'tenant-x',
    aad: 'tenant-x|epoch=3',
  });
  process.env[SEALED_SHARD_DESCRIPTOR_ENV] = descriptorPath;
  process.env.ENTERPRISE_MASTER_KEY = Buffer.alloc(32, 9).toString('base64');

  const cfg = loadSealedShardDescriptor();
  assert.ok(cfg, 'fully configured sealed path must resolve');
  assert.equal(cfg!.descriptor.salt, 'tenant-x');
  assert.equal(cfg!.descriptor.aad, 'tenant-x|epoch=3');
  assert.equal(cfg!.licenseJwt, 'fake-header.fake-payload.fake-signature');
  assert.equal(cfg!.secretRootB64, process.env.ENTERPRISE_MASTER_KEY);
  assert.ok(cfg!.publicKeyPem.includes('BEGIN PUBLIC KEY'));

  clearEnv();
  process.env.HOME = realHome;
});

// ── Dogfood-ready 4.0: default descriptor location + seal_secret root ──────
//
// Failure classes: env-over-default precedence; default present/absent;
// default present as a non-file (directory, dangling symlink) must DECLARE
// sealed (fail closed), not silently select plaintext; seal_secret
// precedence over ENTERPRISE_MASTER_KEY; malformed seal_secret must fail
// closed and never fall back to ENTERPRISE_MASTER_KEY.

const VALID_DESCRIPTOR = {
  ciphertextB64: 'Q0lQSEVSVEVYVA==',
  ivB64: 'IV',
  signatureB64: 'SIG',
  salt: '2026.10.14',
  aad: '2026.10.14|epoch=1',
};

function writeLicenseEnvelopeWith(home: string, extra: Record<string, unknown>): void {
  const dir = join(home, '.epic-ai');
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, 'chariot.license'),
    JSON.stringify({ jwt: 'fake-header.fake-payload.fake-signature', renewal_secret: 'unused-in-this-test', ...extra }),
  );
}

function writeDefaultDescriptor(baseDir: string, body: unknown = VALID_DESCRIPTOR): string {
  const p = defaultSealedShardDescriptorPath(baseDir);
  mkdirSync(join(baseDir, 'edgeshard'), { recursive: true });
  writeFileSync(p, JSON.stringify(body));
  return p;
}

test('default descriptor path is <EPIC_AI_DIR>/edgeshard/catalog.edgeshard.sealed', () => {
  assert.equal(defaultSealedShardDescriptorPath('/x/y'), join('/x/y', 'edgeshard', 'catalog.edgeshard.sealed'));
  assert.equal(
    defaultSealedShardDescriptorPath(),
    join(epicAiDirSandbox, 'edgeshard', 'catalog.edgeshard.sealed'),
    'no-arg default must hang off EPIC_AI_DIR (EPIC_AI_DIR_OVERRIDE honoured)',
  );
});

test('resolve: env unset + default absent → null (today\'s "not configured")', () => {
  clearEnv();
  const base = mkdtempSync(join(tmpdir(), 'chariot-sealed-default-absent-'));
  assert.equal(resolveSealedShardDescriptorPath(base), null);
  assert.equal(loadSealedShardDescriptor(resolveSealedShardDescriptorPath(base)), null);
});

test('resolve: env unset + default file present → the default path', () => {
  clearEnv();
  const base = mkdtempSync(join(tmpdir(), 'chariot-sealed-default-present-'));
  const p = writeDefaultDescriptor(base);
  assert.equal(resolveSealedShardDescriptorPath(base), p);
});

test('resolve: env set wins over a present default (even when the env file is missing)', () => {
  clearEnv();
  const base = mkdtempSync(join(tmpdir(), 'chariot-sealed-env-wins-'));
  writeDefaultDescriptor(base);
  const envPath = join(base, 'operator-chosen-missing.json');
  process.env[SEALED_SHARD_DESCRIPTOR_ENV] = envPath;
  assert.equal(resolveSealedShardDescriptorPath(base), envPath);
  // configured-but-broken env path → fail closed, never "use the default instead"
  assert.equal(loadSealedShardDescriptor(resolveSealedShardDescriptorPath(base)), null);
  clearEnv();
});

test('resolve: env set to the empty string is treated as unset (pre-existing truthiness semantics)', () => {
  clearEnv();
  const base = mkdtempSync(join(tmpdir(), 'chariot-sealed-env-empty-'));
  process.env[SEALED_SHARD_DESCRIPTOR_ENV] = '';
  assert.equal(resolveSealedShardDescriptorPath(base), null);
  const p = writeDefaultDescriptor(base);
  assert.equal(resolveSealedShardDescriptorPath(base), p);
  clearEnv();
});

test('resolve: default present as a DIRECTORY declares sealed and the load fails closed', () => {
  clearEnv();
  const base = mkdtempSync(join(tmpdir(), 'chariot-sealed-default-dir-'));
  const p = defaultSealedShardDescriptorPath(base);
  mkdirSync(p, { recursive: true });
  assert.equal(resolveSealedShardDescriptorPath(base), p);
  assert.equal(loadSealedShardDescriptor(p), null);
});

test('resolve: default present as a DANGLING symlink declares sealed (no silent plaintext fallback)', () => {
  clearEnv();
  const base = mkdtempSync(join(tmpdir(), 'chariot-sealed-default-dangling-'));
  mkdirSync(join(base, 'edgeshard'), { recursive: true });
  const p = defaultSealedShardDescriptorPath(base);
  symlinkSync(join(base, 'nowhere.json'), p);
  assert.equal(resolveSealedShardDescriptorPath(base), p);
  assert.equal(loadSealedShardDescriptor(p), null);
});

test('secret root: a valid licence seal_secret wins over ENTERPRISE_MASTER_KEY', () => {
  clearEnv();
  const home = freshHomeSandbox();
  const seal = randomBytes(32).toString('base64');
  writeLicenseEnvelopeWith(home, { seal_secret: seal });
  const p = writeDefaultDescriptor(home);
  process.env.ENTERPRISE_MASTER_KEY = Buffer.alloc(32, 9).toString('base64');
  const cfg = loadSealedShardDescriptor(p);
  assert.ok(cfg);
  assert.equal(cfg!.secretRootB64, seal);
  assert.notEqual(cfg!.secretRootB64, process.env.ENTERPRISE_MASTER_KEY);
  clearEnv();
});

test('secret root: a valid licence seal_secret suffices with ENTERPRISE_MASTER_KEY unset', () => {
  clearEnv();
  const home = freshHomeSandbox();
  const seal = randomBytes(32).toString('base64');
  writeLicenseEnvelopeWith(home, { seal_secret: seal });
  const p = writeDefaultDescriptor(home);
  const cfg = loadSealedShardDescriptor(p);
  assert.ok(cfg);
  assert.equal(cfg!.secretRootB64, seal);
  clearEnv();
});

test('secret root: no seal_secret → ENTERPRISE_MASTER_KEY (spec alternative unchanged)', () => {
  clearEnv();
  const home = freshHomeSandbox();
  writeLicenseEnvelopeWith(home, {});
  const p = writeDefaultDescriptor(home);
  process.env.ENTERPRISE_MASTER_KEY = Buffer.alloc(32, 5).toString('base64');
  const cfg = loadSealedShardDescriptor(p);
  assert.equal(cfg?.secretRootB64, process.env.ENTERPRISE_MASTER_KEY);
  clearEnv();
});

test('secret root: no seal_secret and no ENTERPRISE_MASTER_KEY → null (fail closed)', () => {
  clearEnv();
  const home = freshHomeSandbox();
  writeLicenseEnvelopeWith(home, {});
  const p = writeDefaultDescriptor(home);
  assert.equal(loadSealedShardDescriptor(p), null);
  clearEnv();
});

test('secret root: a MALFORMED seal_secret fails closed and never falls back to ENTERPRISE_MASTER_KEY', () => {
  for (const bad of ['not-base64', randomBytes(31).toString('base64'), randomBytes(32).toString('base64url'), null, 3]) {
    clearEnv();
    const home = freshHomeSandbox();
    writeLicenseEnvelopeWith(home, { seal_secret: bad });
    const p = writeDefaultDescriptor(home);
    process.env.ENTERPRISE_MASTER_KEY = Buffer.alloc(32, 9).toString('base64');
    assert.equal(loadSealedShardDescriptor(p), null, `seal_secret=${JSON.stringify(bad)} must fail closed`);
  }
  clearEnv();
});

// ── CHARIOT §5.7 file-reference form (AMENDED 2026-10-14) ─────────────────
//
// Spec bytes (CHARIOT-SPEC.md §5.7 "Envelope fields"): `"ciphertext": {
// "file": "<basename>", "sha256": "<hex SHA-256 of that file>" }`, "where
// `file` is a bare basename resolved in the descriptor's own directory and
// naming a regular file, not a symbolic link"; "the inline base64 string form
// (`ciphertextB64`) remains accepted"; "a descriptor carrying both forms is
// refused". Failure classes: happy path (incl. a multi-chunk file); `file`
// not a bare basename (`/`, `\`, `..`, `.`, empty, NUL, non-string); `sha256`
// absent / malformed / uppercase / mismatching; referenced path missing / a
// symlink (live, matching hash) / a directory; both forms present; inline
// alias disagreeing with `ciphertextB64`; legacy equal alias still accepted.

const FILE_FORM_FIELDS = { ivB64: 'IV', signatureB64: 'SIG', salt: '2026.10.14', aad: '2026.10.14|epoch=1' };
const CIPHERTEXT_NAME = 'catalog.edgeshard.sealed.ciphertext';

function fileFormFixture(bytes: Buffer = randomBytes(64)): { dir: string; descriptorPath: string; ciphertextPath: string; sha: string } {
  clearEnv();
  const home = freshHomeSandbox();
  writeLicenseEnvelopeWith(home, { seal_secret: randomBytes(32).toString('base64') });
  const dir = join(home, 'edgeshard');
  mkdirSync(dir, { recursive: true });
  const ciphertextPath = join(dir, CIPHERTEXT_NAME);
  writeFileSync(ciphertextPath, bytes);
  return { dir, descriptorPath: join(dir, 'catalog.edgeshard.sealed'), ciphertextPath, sha: createHash('sha256').update(bytes).digest('hex') };
}

function fileFormDescriptor(ciphertext: unknown, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { ciphertext, iv: 'IV', signature: 'SIG', ...FILE_FORM_FIELDS, ...extra };
}

test('file form: a bare-basename reference with a matching sha256 resolves to ciphertextPath (no inline ciphertext)', () => {
  // > 3 chunks of the 1 MiB streaming digest, plus a partial chunk.
  const f = fileFormFixture(randomBytes(3 * (1 << 20) + 17));
  writeDescriptor(f.descriptorPath, fileFormDescriptor({ file: CIPHERTEXT_NAME, sha256: f.sha }));
  const cfg = loadSealedShardDescriptor(f.descriptorPath);
  assert.ok(cfg, 'a valid file-reference descriptor must resolve');
  assert.deepEqual(cfg!.descriptor, { ciphertextPath: f.ciphertextPath, ciphertextSha256: f.sha, ...FILE_FORM_FIELDS });
  assert.equal('ciphertextB64' in cfg!.descriptor, false);
  clearEnv();
});

test('file form: `file` that is not a bare basename is refused', () => {
  const f = fileFormFixture();
  // A sibling that a traversal/sub-path could reach must still not be accepted.
  mkdirSync(join(f.dir, 'sub'), { recursive: true });
  writeFileSync(join(f.dir, 'sub', CIPHERTEXT_NAME), readFileSync(f.ciphertextPath));
  for (const file of ['', '.', '..', `../${CIPHERTEXT_NAME}`, `sub/${CIPHERTEXT_NAME}`, `sub\\${CIPHERTEXT_NAME}`, `${CIPHERTEXT_NAME}\0`, f.ciphertextPath, 42, null, ['x']]) {
    writeDescriptor(f.descriptorPath, fileFormDescriptor({ file, sha256: f.sha }));
    assert.equal(loadSealedShardDescriptor(f.descriptorPath), null, `file=${JSON.stringify(file)} must be refused`);
  }
  clearEnv();
});

test('file form: a bare basename merely containing ".." (x..y) is accepted (§5.7::61)', () => {
  const f = fileFormFixture();
  writeFileSync(join(f.dir, 'x..y'), readFileSync(f.ciphertextPath));
  writeDescriptor(f.descriptorPath, fileFormDescriptor({ file: 'x..y', sha256: f.sha }));
  const cfg = loadSealedShardDescriptor(f.descriptorPath);
  assert.ok(cfg, 'x..y is a bare basename');
  assert.equal(cfg!.descriptor.ciphertextPath, join(f.dir, 'x..y'));
  clearEnv();
});

test('inline form: ciphertextB64 must be non-empty canonical standard base64 (§5.7::3)', () => {
  const f = fileFormFixture();
  for (const ciphertextB64 of ['', 'x', 'CIPHERTEXT', 'not base64!', 'eA', 'eA=', '-_8=']) {
    writeDescriptor(f.descriptorPath, { ...FILE_FORM_FIELDS, ciphertextB64 });
    assert.equal(loadSealedShardDescriptor(f.descriptorPath), null, `ciphertextB64=${JSON.stringify(ciphertextB64)} must be refused`);
  }
  writeDescriptor(f.descriptorPath, { ...FILE_FORM_FIELDS, ciphertextB64: 'eA==' });
  assert.ok(loadSealedShardDescriptor(f.descriptorPath), 'canonical base64 is accepted');
  clearEnv();
});

test('file form: sha256 absent, malformed, uppercase or mismatching is refused', () => {
  const f = fileFormFixture();
  const wrong = createHash('sha256').update('different bytes').digest('hex');
  for (const sha256 of [undefined, '', 'abc', f.sha.slice(0, 63), `${f.sha}0`, f.sha.toUpperCase(), `${f.sha.slice(0, 63)}g`, wrong, 7]) {
    const ref = sha256 === undefined ? { file: CIPHERTEXT_NAME } : { file: CIPHERTEXT_NAME, sha256 };
    writeDescriptor(f.descriptorPath, fileFormDescriptor(ref));
    assert.equal(loadSealedShardDescriptor(f.descriptorPath), null, `sha256=${JSON.stringify(sha256)} must be refused`);
  }
  clearEnv();
});

test('file form: a missing ciphertext file is refused', () => {
  const f = fileFormFixture();
  writeDescriptor(f.descriptorPath, fileFormDescriptor({ file: 'absent.ciphertext', sha256: f.sha }));
  assert.equal(loadSealedShardDescriptor(f.descriptorPath), null);
  clearEnv();
});

test('file form: a SYMLINKED ciphertext is refused even when its target hash matches', () => {
  const f = fileFormFixture();
  const link = join(f.dir, 'linked.ciphertext');
  symlinkSync(f.ciphertextPath, link);
  writeDescriptor(f.descriptorPath, fileFormDescriptor({ file: 'linked.ciphertext', sha256: f.sha }));
  assert.equal(loadSealedShardDescriptor(f.descriptorPath), null, 'a symbolic link is not a regular file');
  // Control: the same sha256 against the real file resolves.
  writeDescriptor(f.descriptorPath, fileFormDescriptor({ file: CIPHERTEXT_NAME, sha256: f.sha }));
  assert.ok(loadSealedShardDescriptor(f.descriptorPath));
  clearEnv();
});

test('file form: a DIRECTORY at the referenced name is refused', () => {
  const f = fileFormFixture();
  mkdirSync(join(f.dir, 'dir.ciphertext'));
  writeDescriptor(f.descriptorPath, fileFormDescriptor({ file: 'dir.ciphertext', sha256: f.sha }));
  assert.equal(loadSealedShardDescriptor(f.descriptorPath), null);
  clearEnv();
});

test('both ciphertext forms present → refused as ambiguous (never resolved by preference)', () => {
  const f = fileFormFixture();
  writeDescriptor(f.descriptorPath, fileFormDescriptor({ file: CIPHERTEXT_NAME, sha256: f.sha }, { ciphertextB64: 'Q0lQSEVSVEVYVA==' }));
  assert.equal(loadSealedShardDescriptor(f.descriptorPath), null);
  clearEnv();
});

test('inline form: a legacy `ciphertext` alias must equal ciphertextB64; a disagreeing or non-string alias is refused', () => {
  const f = fileFormFixture();
  writeDescriptor(f.descriptorPath, { ...FILE_FORM_FIELDS, ciphertextB64: 'Q0lQSEVSVEVYVA==', ciphertext: 'Q0lQSEVSVEVYVA==' });
  const cfg = loadSealedShardDescriptor(f.descriptorPath);
  assert.ok(cfg, 'legacy descriptor with equal alias must still resolve');
  assert.deepEqual(cfg!.descriptor, { ciphertextB64: 'Q0lQSEVSVEVYVA==', ...FILE_FORM_FIELDS });
  for (const alias of ['OTHER', null, 3, ['Q0lQSEVSVEVYVA==']]) {
    writeDescriptor(f.descriptorPath, { ...FILE_FORM_FIELDS, ciphertextB64: 'Q0lQSEVSVEVYVA==', ciphertext: alias });
    assert.equal(loadSealedShardDescriptor(f.descriptorPath), null, `alias=${JSON.stringify(alias)} must be refused`);
  }
  // Inline alias alone (no ciphertextB64) stays malformed, as before.
  writeDescriptor(f.descriptorPath, { ...FILE_FORM_FIELDS, ciphertext: 'Q0lQSEVSVEVYVA==' });
  assert.equal(loadSealedShardDescriptor(f.descriptorPath), null);
  clearEnv();
});

test('no-arg loadSealedShardDescriptor() resolves the module default (<EPIC_AI_DIR>/edgeshard/…) when env is unset', () => {
  clearEnv();
  const home = freshHomeSandbox();
  writeLicenseEnvelopeWith(home, { seal_secret: randomBytes(32).toString('base64') });
  assert.equal(loadSealedShardDescriptor(), null, 'precondition: no default yet');
  const p = writeDefaultDescriptor(epicAiDirSandbox);
  try {
    assert.equal(resolveSealedShardDescriptorPath(), p);
    const cfg = loadSealedShardDescriptor();
    assert.ok(cfg, 'default descriptor + licence seal_secret must resolve with no env at all');
    assert.equal(cfg!.descriptor.salt, VALID_DESCRIPTOR.salt);
  } finally {
    rmSync(join(epicAiDirSandbox, 'edgeshard'), { recursive: true, force: true });
    clearEnv();
    process.env.HOME = realHome;
  }
});
