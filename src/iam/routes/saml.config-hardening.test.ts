/**
 * Prove-on-revert for CHARIOT §10.2::2 — per-tenant SAML config SHALL require
 * signatureAlgorithm:'sha256', wantAssertionsSigned:true, wantAuthnResponseSigned:true.
 *
 * Defect this catches: wantAssertionsSigned/wantAuthnResponseSigned were
 * `z.boolean().default(true)`, so a tenant could set them to `false` and receive
 * a SAML config that accepts UNSIGNED assertions/responses. Pinned to
 * `z.literal(true)`; saml.ts additionally hard-pins them at the point of use.
 *
 * Run (after tsc): node --test dist/iam/routes/saml.config-hardening.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { samlConfigSchema } from '../schemas.js';

const base = {
  entryPoint: 'https://idp.example.com/sso',
  issuer: 'chariot-sp',
  cert: 'C'.repeat(120),
  callbackUrl: 'https://sp.example.com/enterprise/t1/auth/saml/callback',
  signatureAlgorithm: 'sha256' as const,
};

test('§10.2::2: rejects wantAssertionsSigned:false (no unsigned assertions)', () => {
  const r = samlConfigSchema.safeParse({ ...base, wantAssertionsSigned: false, wantAuthnResponseSigned: true });
  assert.equal(r.success, false, 'a config disabling assertion signing must be rejected');
});

test('§10.2::2: rejects wantAuthnResponseSigned:false (no unsigned responses)', () => {
  const r = samlConfigSchema.safeParse({ ...base, wantAssertionsSigned: true, wantAuthnResponseSigned: false });
  assert.equal(r.success, false, 'a config disabling authn-response signing must be rejected');
});

test('§10.2::2: rejects signatureAlgorithm sha1 (sha256 required)', () => {
  const r = samlConfigSchema.safeParse({ ...base, signatureAlgorithm: 'sha1' });
  assert.equal(r.success, false, 'sha1 signature algorithm must be rejected');
});

test('§10.2::2: omitted signing flags default to true', () => {
  const r = samlConfigSchema.safeParse(base);
  assert.equal(r.success, true, 'a config with sha256 + required fields is valid');
  if (r.success) {
    assert.equal(r.data.wantAssertionsSigned, true);
    assert.equal(r.data.wantAuthnResponseSigned, true);
  }
});
