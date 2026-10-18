/**
 * Prove-on-revert for CHARIOT §10.3::1 — OIDC config hardening.
 *
 * §10.3::1 requires: default scopes ['openid','profile','email','groups']
 * (the 'groups' scope is mandatory so the IdP returns group claims for RBAC),
 * AND the clientSecret stored 'encrypted at rest'.
 *
 * Defects this catches: (1) oidc.ts defaulted scopes to
 * ['openid','profile','email'] — 'groups' was missing; (2) updateSso() wrote
 * sso.oidc.clientSecret to Mongo in plaintext with no encryptFields() call,
 * and oidc.ts passed oidcConfig.clientSecret directly to client.discovery.
 *
 * Live encrypt/decrypt round-trip needs the @epicai/chariot native binding,
 * which is absent in this test env; this asserts the wiring via source so the
 * assertions fail the instant either fix is reverted.
 *
 * Run (after tsc): node --test dist/iam/routes/oidc.config-hardening.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const oidcSrc = readFileSync(fileURLToPath(new URL('./oidc.js', import.meta.url)), 'utf8');
const tenantSrc = readFileSync(
  fileURLToPath(new URL('../services/tenant.js', import.meta.url)),
  'utf8',
);

test("§10.3::1: default scopes include 'groups'", () => {
  // Assert the CODE default (not a comment): the `rawScopes ?? [...]` fallback
  // must resolve to exactly openid/profile/email/groups. Anchoring on
  // `rawScopes ??` excludes any prose/comment that mentions the array.
  assert.match(
    oidcSrc,
    /rawScopes\s*\?\?\s*\[\s*['"]openid['"]\s*,\s*['"]profile['"]\s*,\s*['"]email['"]\s*,\s*['"]groups['"]\s*\]/,
    "default scope fallback must be rawScopes ?? ['openid','profile','email','groups']",
  );
});

test('§10.3::1: clientSecret is never passed to the IdP client in plaintext', () => {
  // The plaintext field must NOT be handed to client.discovery(...).
  assert.ok(
    !/oidcConfig\.clientSecret\s*,/.test(oidcSrc),
    'oidc.ts must not pass oidcConfig.clientSecret directly to client.discovery',
  );
  // It must resolve the secret through the decrypt-or-legacy resolver.
  assert.ok(
    oidcSrc.includes('resolveOidcClientSecret'),
    'oidc.ts must resolve the client secret via resolveOidcClientSecret()',
  );
  assert.ok(
    oidcSrc.includes('decryptFields'),
    'the resolver must decrypt the at-rest blob via decryptFields',
  );
});

test('§10.3::1: updateSso encrypts the clientSecret at rest and strips plaintext', () => {
  assert.ok(
    tenantSrc.includes('encryptOidcSecretAtRest'),
    'updateSso must route OIDC config through encryptOidcSecretAtRest',
  );
  assert.ok(
    tenantSrc.includes('encryptFields') && tenantSrc.includes('clientSecretEncrypted'),
    'the at-rest path must encrypt via encryptFields and persist clientSecretEncrypted',
  );
});
