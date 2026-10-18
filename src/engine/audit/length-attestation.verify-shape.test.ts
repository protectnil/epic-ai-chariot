/**
 * @epicai/chariot — verifyLengthAttestation literal-signature conformance
 *
 * CHARIOT::§9.8.3::3 — "The verifier API verifyLengthAttestation(att,
 * publicKeyPem) SHALL return {valid, attestedAt, chainId, attestedLength,
 * error?}."
 *
 * Spec, CHARIOT-SPEC.md §9.8.3 (Verifier API surface):
 *   "verifyLengthAttestation(att: LengthAttestation, publicKeyPem: string): Promise<AttestationVerifyResult>"
 *   "Returns {valid: boolean, attestedAt: Date, chainId: string, attestedLength: number, error?: string}."
 *
 * Failure classes enumerated per the ZERO-DEFECT method:
 *   - return TYPE (must be a Promise, not a bare boolean/object)
 *   - each resolved field's presence + runtime type on the success path
 *   - each resolved field's presence + runtime type on a failure path
 *     (tampered signature) — `error` becomes present, others stay typed
 *   - malformed input never throws/rejects (documented contract carried
 *     over from the pre-existing boolean-returning implementation)
 *
 * Run (after tsc): node --test dist/engine/audit/length-attestation.verify-shape.test.js
 * Registered in scripts/run-all-tests.mjs.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createHash } from 'node:crypto';
import {
  verifyLengthAttestation,
  signLengthAttestation,
  type LengthAttestation,
  type AttestationVerifyResult,
} from './length-attestation.js';

// Type-level: the exported verifyLengthAttestation signature equals the
// spec's literal signature byte-for-byte. If the implementation's params
// or return type drift from (att: LengthAttestation, publicKeyPem: string)
// => Promise<AttestationVerifyResult>, this assignment fails to compile.
const _typeCheck: (att: LengthAttestation, publicKeyPem: string) => Promise<AttestationVerifyResult> =
  verifyLengthAttestation;
void _typeCheck;

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const pubPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;

function makeAttestation(length: number, chainId: string): LengthAttestation {
  return signLengthAttestation(
    {
      schemaVersion: 1,
      chainId,
      length,
      headHash: createHash('sha256').update(`h-${chainId}-${length}`).digest('hex'),
      attestedAt: '2026-09-01T00:00:00.000Z',
    },
    privPem,
  );
}

test('CHARIOT::§9.8.3::3 — verifyLengthAttestation returns a Promise', () => {
  const att = makeAttestation(1, 'chain-shape-promise');
  const result = verifyLengthAttestation(att, pubPem);
  assert.ok(result instanceof Promise, 'verifyLengthAttestation must return a Promise');
});

test('CHARIOT::§9.8.3::3 — resolved object has valid:boolean(true), attestedAt:Date, chainId:string, attestedLength:number, no error on a valid attestation', async () => {
  const att = makeAttestation(42, 'chain-shape-valid');
  const result = await verifyLengthAttestation(att, pubPem);
  assert.equal(typeof result.valid, 'boolean');
  assert.equal(result.valid, true);
  assert.ok(result.attestedAt instanceof Date, 'attestedAt must be a Date');
  assert.equal(result.attestedAt.toISOString(), '2026-09-01T00:00:00.000Z');
  assert.equal(typeof result.chainId, 'string');
  assert.equal(result.chainId, 'chain-shape-valid');
  assert.equal(typeof result.attestedLength, 'number');
  assert.equal(result.attestedLength, 42);
  assert.equal(result.error, undefined, 'error must be absent on success');
});

test('CHARIOT::§9.8.3::3 — resolved object carries error:string on a tampered-length attestation; other fields stay typed', async () => {
  const att = makeAttestation(7, 'chain-shape-tampered');
  const tampered = { ...att, length: 8 };
  const result = await verifyLengthAttestation(tampered, pubPem);
  assert.equal(result.valid, false);
  assert.equal(typeof result.error, 'string');
  assert.ok((result.error ?? '').length > 0, 'error must be non-empty when valid:false');
  assert.ok(result.attestedAt instanceof Date);
  assert.equal(result.chainId, 'chain-shape-tampered');
  assert.equal(result.attestedLength, 8);
});

test('CHARIOT::§9.8.3::3 — resolved object carries error:string on a wrong-key verification', async () => {
  const att = makeAttestation(3, 'chain-shape-wrongkey');
  const { publicKey: otherPub } = generateKeyPairSync('ed25519');
  const result = await verifyLengthAttestation(att, otherPub.export({ type: 'spki', format: 'pem' }) as string);
  assert.equal(result.valid, false);
  assert.equal(typeof result.error, 'string');
  assert.ok((result.error ?? '').length > 0);
});

test('CHARIOT::§9.8.3::3 — malformed input never throws/rejects; resolves valid:false with an error', async () => {
  await assert.doesNotReject(async () => {
    const malformed = {
      schemaVersion: 1,
      chainId: 'chain-shape-malformed',
      length: -1,
      headHash: '',
      attestedAt: 'not-a-date',
      signature: '',
    } as LengthAttestation;
    const result = await verifyLengthAttestation(malformed, pubPem);
    assert.equal(result.valid, false);
    assert.equal(typeof result.error, 'string');
    assert.equal(result.chainId, 'chain-shape-malformed');
  });
});
