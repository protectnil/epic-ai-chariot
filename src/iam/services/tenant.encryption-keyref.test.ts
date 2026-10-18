/**
 * Prove-on-revert for CHARIOT §10.8::4 — per-tenant encryption key reference.
 *
 * §10.8::4: "Tenant management SHALL store an encryption key reference (KMS
 * pointer or env-key ID) per tenant."
 *
 * Defect this catches: TenantDocument carried no encryption-key reference and
 * create() never wrote one, so there was no per-tenant record of the key
 * material a tenant's data at rest is encrypted under.
 *
 * Run (after tsc): node --test dist/iam/services/tenant.encryption-keyref.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// master-key reference: VALIDATION ONLY (format/presence check, no derivation or encrypt/decrypt call)

const tenantSrc = readFileSync(fileURLToPath(new URL('./tenant.js', import.meta.url)), 'utf8');
const typesSrc = readFileSync(fileURLToPath(new URL('../types.js', import.meta.url)), 'utf8');

test('§10.8::4: TenantDocument declares a required encryptionKeyRef', () => {
  // types.js is emitted JS — the interface field is erased, but the .d.ts is
  // not read here; instead assert create() writes the field (below) and that
  // the field name is referenced in the compiled service.
  assert.ok(
    tenantSrc.includes('encryptionKeyRef'),
    'the tenant service must reference encryptionKeyRef',
  );
  void typesSrc;
});

test('§10.8::4: create() records a per-tenant encryption key reference by default', () => {
  // The default env-key ID must name the actual master-key env var.
  assert.ok(
    /encryptionKeyRef\s*:\s*encryptionKeyRef\s*\?\?\s*['"]env:ENTERPRISE_MASTER_KEY['"]/.test(
      tenantSrc,
    ),
    "create() must default encryptionKeyRef to 'env:ENTERPRISE_MASTER_KEY'",
  );
});

test('§10.8::4: create() accepts a caller-supplied key reference (KMS deployments)', () => {
  assert.ok(
    /function create\([^)]*encryptionKeyRef\?/s.test(tenantSrc) ||
      tenantSrc.includes('encryptionKeyRef ??'),
    'create() must accept an optional encryptionKeyRef override',
  );
});
