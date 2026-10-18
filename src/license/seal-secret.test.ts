/**
 * Dogfood-ready 4.0 contract — the licence envelope's OPTIONAL `seal_secret`
 * (CHARIOT-SPEC §5.7: the secret root is "a per-license secret key or
 * ENTERPRISE_MASTER_KEY"). Envelope = `{ jwt, renewal_secret, seal_secret? }`;
 * `seal_secret` is standard padded base64 of exactly 32 bytes, issued once,
 * NEVER rotated by renewal, and NEVER a factor in licence validity.
 *
 * Failure classes covered (tests derived from these, not from the code):
 *   value     — wrong decoded length (31/33 bytes), base64url alphabet,
 *               missing/extra padding, embedded whitespace, non-canonical
 *               trailing bits, non-string JSON types (number/null/object/
 *               bool), empty string;
 *   presence  — absent vs present-valid vs present-malformed on read;
 *   licence   — a malformed seal_secret must not null the envelope nor
 *               change licence validation's verdict;
 *   activate  — parse keeps the field verbatim (valid or not), write emits
 *               it only when present, mode 0600, round-trips through the
 *               loader; seal_secret never changes an activation rejection;
 *   renewal   — the held value is carried forward verbatim (valid, raw
 *               malformed incl. JSON null), absent stays absent, a value
 *               smuggled in the renew response is ignored; the same helper
 *               builds the rollback envelope.
 *
 * The renewal/activation SUCCESS paths need a JWT signed by the production
 * licence key (loader.ts has no test-key seam, by design), so the write
 * contents are proven through the exported pure pieces those paths call
 * (`parseEnvelope`, `writeLicenseEnvelopeAtomic`,
 * `envelopeWithHeldSealSecret`).
 *
 * `process.env.HOME` is redirected to a sandbox: `loader.ts::getLicensePath()`
 * is built on `os.homedir()`, which reads `$HOME` on every call.
 *
 * Run (after tsc): node --test dist/license/seal-secret.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';

const realHome = process.env.HOME;

const {
  validateSealSecret,
  readLicenseEnvelope,
  validateLicense,
  __resetLicenseCache,
  SEAL_SECRET_BYTES,
} = await import('./loader.js');
const { parseEnvelope, writeLicenseEnvelopeAtomic, activateLicenseFromPath } = await import('./activate.js');
const { envelopeWithHeldSealSecret } = await import('./renew-client.js');

function sandboxHome(): string {
  const home = mkdtempSync(join(tmpdir(), 'chariot-seal-secret-home-'));
  process.env.HOME = home;
  return home;
}

function restoreHome(): void {
  process.env.HOME = realHome;
}

function writeEnvelopeRaw(home: string, body: unknown): string {
  const dir = join(home, '.epic-ai');
  mkdirSync(dir, { recursive: true });
  const p = join(dir, 'chariot.license');
  writeFileSync(p, typeof body === 'string' ? body : JSON.stringify(body));
  return p;
}

const VALID = randomBytes(32).toString('base64');

// ── validateSealSecret ─────────────────────────────────────────────────────

test('validateSealSecret: canonical padded base64 of exactly 32 bytes is accepted', () => {
  assert.equal(SEAL_SECRET_BYTES, 32);
  const r = validateSealSecret(VALID);
  assert.deepEqual(r, { ok: true, value: VALID });
  // all-zero and all-0xff boundary byte values
  assert.equal(validateSealSecret(Buffer.alloc(32, 0).toString('base64')).ok, true);
  assert.equal(validateSealSecret(Buffer.alloc(32, 0xff).toString('base64')).ok, true);
});

test('validateSealSecret: wrong decoded length (31, 33, 0 bytes) is rejected', () => {
  assert.equal(validateSealSecret(randomBytes(31).toString('base64')).ok, false);
  assert.equal(validateSealSecret(randomBytes(33).toString('base64')).ok, false);
  assert.equal(validateSealSecret('').ok, false);
});

test('validateSealSecret: base64url alphabet, missing/extra padding and whitespace are rejected', () => {
  // Force both url-alphabet characters into an otherwise valid 32-byte value.
  const bytes = Buffer.alloc(32, 0xfb); // 0xfb… encodes with '+' and '/' runs
  const std = bytes.toString('base64');
  assert.ok(/[+/]/.test(std), 'fixture must contain a std-alphabet-only char');
  assert.equal(validateSealSecret(bytes.toString('base64url')).ok, false, 'base64url (no padding, -_ alphabet)');
  assert.equal(validateSealSecret(std.replace(/\+/g, '-').replace(/\//g, '_')).ok, false, 'base64url alphabet with padding');
  assert.equal(validateSealSecret(VALID.slice(0, -1)).ok, false, 'padding stripped (43 chars)');
  assert.equal(validateSealSecret(`${VALID}=`).ok, false, 'extra padding');
  assert.equal(validateSealSecret(` ${VALID}`).ok, false, 'leading space');
  assert.equal(validateSealSecret(`${VALID}\n`).ok, false, 'trailing newline');
  assert.equal(validateSealSecret(`${VALID.slice(0, 20)}\n${VALID.slice(20)}`).ok, false, 'embedded newline');
});

test('validateSealSecret: non-canonical trailing bits (lenient decoder would accept) are rejected', () => {
  // 32 bytes = 256 bits; the 43rd char carries 4 data bits + 2 zero pad
  // bits. Set a pad bit: same decoded bytes, different string.
  const zero = Buffer.alloc(32, 0).toString('base64'); // 'AAAA…AAA='
  const nonCanonical = `${zero.slice(0, 42)}B=`; // 'B' = 0b000001 → pad bit set
  assert.equal(Buffer.from(nonCanonical, 'base64').length, 32, 'fixture: Node decodes it to 32 bytes');
  assert.equal(validateSealSecret(nonCanonical).ok, false);
});

test('validateSealSecret: non-string JSON values are rejected, never thrown on', () => {
  for (const v of [null, undefined, 42, true, {}, [], { value: VALID }]) {
    const r = validateSealSecret(v);
    assert.equal(r.ok, false, `value ${JSON.stringify(v)} must be rejected`);
  }
});

// ── readLicenseEnvelope ────────────────────────────────────────────────────

test('readLicenseEnvelope: seal_secret absent → neither seal_secret nor seal_secret_error', () => {
  const home = sandboxHome();
  try {
    writeEnvelopeRaw(home, { jwt: 'h.p.s', renewal_secret: 'rs' });
    const env = readLicenseEnvelope();
    assert.ok(env);
    assert.equal(env!.jwt, 'h.p.s');
    assert.equal(env!.renewal_secret, 'rs');
    assert.equal(env!.seal_secret, undefined);
    assert.equal(env!.seal_secret_error, undefined);
  } finally {
    restoreHome();
  }
});

test('readLicenseEnvelope: valid seal_secret → exposed as seal_secret', () => {
  const home = sandboxHome();
  try {
    writeEnvelopeRaw(home, { jwt: 'h.p.s', renewal_secret: 'rs', seal_secret: VALID });
    const env = readLicenseEnvelope();
    assert.equal(env?.seal_secret, VALID);
    assert.equal(env?.seal_secret_error, undefined);
  } finally {
    restoreHome();
  }
});

test('readLicenseEnvelope: malformed seal_secret → envelope still returned, error carries reason + raw value', () => {
  const home = sandboxHome();
  try {
    for (const bad of ['not-base64!', randomBytes(31).toString('base64'), 7, null, { k: 1 }, '']) {
      writeEnvelopeRaw(home, { jwt: 'h.p.s', renewal_secret: 'rs', seal_secret: bad });
      const env = readLicenseEnvelope();
      assert.ok(env, `envelope must not be nulled by seal_secret=${JSON.stringify(bad)}`);
      assert.equal(env!.jwt, 'h.p.s');
      assert.equal(env!.seal_secret, undefined);
      assert.ok(env!.seal_secret_error, 'seal_secret_error must be set');
      assert.equal(typeof env!.seal_secret_error!.reason, 'string');
      assert.deepEqual(env!.seal_secret_error!.raw, bad);
    }
  } finally {
    restoreHome();
  }
});

test('readLicenseEnvelope: licence-half defects still null the envelope (unchanged), with or without seal_secret', () => {
  const home = sandboxHome();
  try {
    writeEnvelopeRaw(home, { renewal_secret: 'rs', seal_secret: VALID });
    assert.equal(readLicenseEnvelope(), null, 'missing jwt');
    writeEnvelopeRaw(home, { jwt: 'h.p.s', seal_secret: VALID });
    assert.equal(readLicenseEnvelope(), null, 'missing renewal_secret');
    writeEnvelopeRaw(home, 'not json');
    assert.equal(readLicenseEnvelope(), null, 'unparseable file');
  } finally {
    restoreHome();
  }
});

test('validateLicense: a malformed seal_secret does not crash nor change the licence verdict', () => {
  const home = sandboxHome();
  const savedEnterprise = process.env.CHARIOT_ENTERPRISE;
  delete process.env.CHARIOT_ENTERPRISE;
  try {
    writeEnvelopeRaw(home, { jwt: 'h.p.s', renewal_secret: 'rs' });
    __resetLicenseCache();
    const baseline = validateLicense();
    writeEnvelopeRaw(home, { jwt: 'h.p.s', renewal_secret: 'rs', seal_secret: 'garbage' });
    __resetLicenseCache();
    let withBad: ReturnType<typeof validateLicense> | undefined;
    assert.doesNotThrow(() => {
      withBad = validateLicense();
    });
    assert.equal(withBad!.mode, baseline.mode);
    assert.equal(withBad!.valid, baseline.valid);
    assert.equal(withBad!.reason, baseline.reason);
  } finally {
    __resetLicenseCache();
    if (savedEnterprise === undefined) delete process.env.CHARIOT_ENTERPRISE;
    else process.env.CHARIOT_ENTERPRISE = savedEnterprise;
    restoreHome();
  }
});

// ── activate.ts ────────────────────────────────────────────────────────────

test('activate parseEnvelope: keeps a valid seal_secret', () => {
  const env = parseEnvelope(JSON.stringify({ jwt: 'h.p.s', renewal_secret: 'rs', seal_secret: VALID }));
  assert.deepEqual(env, { jwt: 'h.p.s', renewal_secret: 'rs', seal_secret: VALID });
});

test('activate parseEnvelope: keeps a malformed seal_secret verbatim (incl. JSON null) — never rejects for it', () => {
  for (const bad of ['short', null, 0, { a: 1 }]) {
    const env = parseEnvelope(JSON.stringify({ jwt: 'h.p.s', renewal_secret: 'rs', seal_secret: bad }));
    assert.ok(env, `seal_secret=${JSON.stringify(bad)} must not reject the envelope`);
    assert.ok(Object.prototype.hasOwnProperty.call(env, 'seal_secret'));
    assert.deepEqual(env!.seal_secret, bad);
  }
});

test('activate parseEnvelope: absent seal_secret → no seal_secret key at all', () => {
  const env = parseEnvelope(JSON.stringify({ jwt: 'h.p.s', renewal_secret: 'rs' }));
  assert.ok(env);
  assert.equal(Object.prototype.hasOwnProperty.call(env, 'seal_secret'), false);
});

test('writeLicenseEnvelopeAtomic: writes seal_secret when present (0600) and round-trips through the loader', () => {
  const home = sandboxHome();
  try {
    const dest = join(home, '.epic-ai', 'chariot.license');
    writeLicenseEnvelopeAtomic({ jwt: 'h.p.s', renewal_secret: 'rs', seal_secret: VALID }, dest);
    const onDisk = JSON.parse(readFileSync(dest, 'utf8')) as Record<string, unknown>;
    assert.deepEqual(Object.keys(onDisk), ['jwt', 'renewal_secret', 'seal_secret']);
    assert.equal(onDisk.seal_secret, VALID);
    assert.equal(statSync(dest).mode & 0o777, 0o600);
    assert.equal(readLicenseEnvelope()?.seal_secret, VALID);
  } finally {
    restoreHome();
  }
});

test('writeLicenseEnvelopeAtomic: omits seal_secret when undefined; writes a malformed raw value verbatim', () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-seal-secret-write-'));
  const a = join(dir, 'a.license');
  writeLicenseEnvelopeAtomic({ jwt: 'h.p.s', renewal_secret: 'rs' }, a);
  assert.deepEqual(Object.keys(JSON.parse(readFileSync(a, 'utf8'))), ['jwt', 'renewal_secret']);
  const b = join(dir, 'b.license');
  writeLicenseEnvelopeAtomic({ jwt: 'h.p.s', renewal_secret: 'rs', seal_secret: null }, b);
  const onDiskB = JSON.parse(readFileSync(b, 'utf8')) as Record<string, unknown>;
  assert.ok(Object.prototype.hasOwnProperty.call(onDiskB, 'seal_secret'));
  assert.equal(onDiskB.seal_secret, null);
});

test('activateLicenseFromPath: seal_secret never changes a rejection (bad JWT → invalid_signature, nothing written)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-seal-secret-activate-'));
  const src = join(dir, 'in.license');
  const dest = join(dir, 'out', 'chariot.license');
  for (const seal of [VALID, 'garbage']) {
    writeFileSync(src, JSON.stringify({ jwt: 'h.p.s', renewal_secret: 'rs', seal_secret: seal }));
    const r = activateLicenseFromPath(src, dest);
    assert.equal(r.ok, false);
    assert.equal(r.ok === false ? r.reason : null, 'invalid_signature');
  }
  writeFileSync(src, JSON.stringify({ jwt: 'h.p.s', seal_secret: VALID }));
  const r2 = activateLicenseFromPath(src, dest);
  assert.equal(r2.ok === false ? r2.reason : null, 'invalid_envelope', 'seal_secret cannot stand in for renewal_secret');
  let exists = true;
  try {
    statSync(dest);
  } catch {
    exists = false;
  }
  assert.equal(exists, false, 'a rejected activation must not write the destination');
});

// ── renew-client.ts ────────────────────────────────────────────────────────

test('renewal: a held valid seal_secret is carried into the renewed envelope', () => {
  const out = envelopeWithHeldSealSecret(
    { jwt: 'new.jwt.x', renewal_secret: 'new-rs' },
    { jwt: 'old.jwt.x', renewal_secret: 'old-rs', seal_secret: VALID },
  );
  assert.deepEqual(out, { jwt: 'new.jwt.x', renewal_secret: 'new-rs', seal_secret: VALID });
});

test('renewal: a held MALFORMED seal_secret is carried forward raw (incl. JSON null), never dropped', () => {
  for (const raw of ['garbage', null, 12]) {
    const out = envelopeWithHeldSealSecret(
      { jwt: 'new.jwt.x', renewal_secret: 'new-rs' },
      { jwt: 'old', renewal_secret: 'old-rs', seal_secret_error: { reason: 'bad', raw } },
    );
    assert.ok(Object.prototype.hasOwnProperty.call(out, 'seal_secret'), `raw=${JSON.stringify(raw)} must be kept`);
    assert.deepEqual(out.seal_secret, raw);
  }
});

test('renewal: no held seal_secret → renewed envelope has none', () => {
  const out = envelopeWithHeldSealSecret(
    { jwt: 'new.jwt.x', renewal_secret: 'new-rs' },
    { jwt: 'old', renewal_secret: 'old-rs' },
  );
  assert.equal(Object.prototype.hasOwnProperty.call(out, 'seal_secret'), false);
});

test('renewal: a seal_secret smuggled in the renew response is ignored — the held value wins (never rotated)', () => {
  const rotated = randomBytes(32).toString('base64');
  const responseLike = { jwt: 'new.jwt.x', renewal_secret: 'new-rs', seal_secret: rotated } as {
    jwt: string;
    renewal_secret: string;
  };
  const kept = envelopeWithHeldSealSecret(responseLike, { jwt: 'old', renewal_secret: 'old-rs', seal_secret: VALID });
  assert.equal(kept.seal_secret, VALID);
  const none = envelopeWithHeldSealSecret(responseLike, { jwt: 'old', renewal_secret: 'old-rs' });
  assert.equal(Object.prototype.hasOwnProperty.call(none, 'seal_secret'), false);
});

test('renewal rollback: rebuilding the held envelope keeps its seal_secret (same helper as the forward write)', () => {
  const held = { jwt: 'old.jwt.x', renewal_secret: 'old-rs', seal_secret: VALID };
  const restored = envelopeWithHeldSealSecret({ jwt: held.jwt, renewal_secret: held.renewal_secret }, held);
  assert.deepEqual(restored, held);
});

test('renew-client source: both envelope writes go through envelopeWithHeldSealSecret', () => {
  const src = readFileSync(new URL('./renew-client.js', import.meta.url), 'utf8');
  const calls = src.match(/writeLicenseEnvelopeAtomic\(\s*envelopeWithHeldSealSecret\(/g) ?? [];
  assert.equal(calls.length, 2, 'renewed write and rollback write must both carry the held seal_secret');
});
