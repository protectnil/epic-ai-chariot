/**
 * @epicai/chariot — Adversarial eval for CHARIOT::§9.8.1::2 custody check
 * (gate finding F4: "logging caller identity is not proof.")
 *
 * Failure classes enumerated from CHARIOT-SPEC.md §9.8.1 (docs/spec/CHARIOT-SPEC.md:899-906),
 * "Key access MUST be gated by the same MFA and RBAC controls used for
 * production database root credentials":
 *   1. kms: every Allow-kms:Sign statement carries an
 *      aws:MultiFactorAuthPresent condition → passes.
 *   2. kms: at least one Allow-kms:Sign statement LACKS that condition →
 *      fails, naming the ungated statement.
 *   3. kms: no Allow-kms:Sign statement at all → fails (nothing reachable
 *      to confirm MFA gating against).
 *   4. vault-transit: MFA login-enforcement covers the token's auth mount,
 *      the token carries a scoped (non-default/root) policy, and that
 *      policy grants sign-only access to the key → passes.
 *   5. vault-transit: no login-enforcement configuration → fails.
 *   6. vault-transit: enforcement exists but the token carries only
 *      default/root policies → fails.
 *   7. vault-transit: enforcement + scoped policy exist, but no policy
 *      grants update/create on transit/sign/<key> → fails (2026-09-04
 *      completion — the policy-body gap named in an earlier revision is
 *      now closed).
 *   8. vault-transit: a scoped policy grants sign AND grants `delete` on
 *      transit/keys/<key> (or export) → fails (broad key control exceeds
 *      production-DB-root-equivalent scoping).
 *   9. sealed-store: single-user mode → always passes, NOT checkable
 *      (MFA/RBAC not applicable outside enterprise mode).
 *  10. sealed-store: enterprise mode, no attestation env var → fails,
 *      NOT checkable (no API surface exists to verify this backend).
 *  11. sealed-store: enterprise mode, CHARIOT_AUDIT_CUSTODY_ATTESTED=1 →
 *      passes, but still NOT checkable (an attestation, not a verification).
 *
 * Run after `tsc`: node --test dist/engine/audit/custodyCheck.test.js
 * Registered in scripts/run-all-tests.mjs.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { checkKmsCustody, checkVaultCustody, checkSealedStoreCustody } from './custodyCheck.js';

function withEnv<T>(vars: Record<string, string | undefined>, fn: () => T): T {
  const prev: Record<string, string | undefined> = {};
  for (const k of Object.keys(vars)) prev[k] = process.env[k];
  for (const [k, v] of Object.entries(vars)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  try {
    return fn();
  } finally {
    for (const [k, v] of Object.entries(prev)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

class FakeGetKeyPolicyCommand {
  constructor(public input: { KeyId: string; PolicyName: string }) {}
}

function fakeKmsFactory(policy: unknown) {
  return () => ({
    send: async () => ({ Policy: JSON.stringify(policy) }),
  });
}

// ── 1-3: kms ──────────────────────────────────────────────────────────────

test('CHARIOT::§9.8.1::2 — kms custody check passes when every Allow-kms:Sign statement requires MFA', async () => {
  const policy = {
    Statement: [
      {
        Sid: 'AllowSignWithMfa',
        Effect: 'Allow',
        Action: 'kms:Sign',
        Condition: { Bool: { 'aws:MultiFactorAuthPresent': 'true' } },
      },
    ],
  };
  const result = await checkKmsCustody('key-1', 'us-east-1', {
    kmsClientFactory: fakeKmsFactory(policy),
    kmsGetKeyPolicyCommandCtor: FakeGetKeyPolicyCommand as never,
  });
  assert.equal(result.passed, true);
  assert.equal(result.checkable, true);
});

test('CHARIOT::§9.8.1::2 — kms custody check fails when an Allow-kms:Sign statement lacks the MFA condition', async () => {
  const policy = {
    Statement: [
      { Sid: 'Gated', Effect: 'Allow', Action: 'kms:Sign', Condition: { Bool: { 'aws:MultiFactorAuthPresent': 'true' } } },
      { Sid: 'Ungated', Effect: 'Allow', Action: 'kms:Sign' },
    ],
  };
  const result = await checkKmsCustody('key-1', 'us-east-1', {
    kmsClientFactory: fakeKmsFactory(policy),
    kmsGetKeyPolicyCommandCtor: FakeGetKeyPolicyCommand as never,
  });
  assert.equal(result.passed, false);
  assert.match(result.reason, /Ungated/);
});

test('CHARIOT::§9.8.1::2 — kms custody check fails when no statement allows kms:Sign at all', async () => {
  const policy = { Statement: [{ Sid: 'OnlyDecrypt', Effect: 'Allow', Action: 'kms:Decrypt' }] };
  const result = await checkKmsCustody('key-1', 'us-east-1', {
    kmsClientFactory: fakeKmsFactory(policy),
    kmsGetKeyPolicyCommandCtor: FakeGetKeyPolicyCommand as never,
  });
  assert.equal(result.passed, false);
  assert.match(result.reason, /no Allow statement for kms:Sign/);
});

// ── 4-8: vault-transit ───────────────────────────────────────────────────

interface FakeVaultOpts {
  policies: string[];
  tokenPath?: string;
  enforcements?: Record<string, { auth_method_types?: string[]; auth_method_accessors?: string[] }>;
  authMounts?: Record<string, { type: string; accessor: string }>;
  policyBodies?: Record<string, string>;
}

function fakeVaultFetch(opts: FakeVaultOpts): typeof fetch {
  const enforcements = opts.enforcements ?? {};
  const authMounts = opts.authMounts ?? {};
  const policyBodies = opts.policyBodies ?? {};
  return (async (url: string | URL, init?: RequestInit) => {
    const u = String(url);
    const method = init?.method ?? 'GET';
    if (u.endsWith('/v1/auth/token/lookup-self')) {
      return new Response(JSON.stringify({ data: { policies: opts.policies, path: opts.tokenPath } }), { status: 200 });
    }
    if (u.endsWith('/v1/identity/mfa/login-enforcement') && method === 'LIST') {
      return new Response(JSON.stringify({ data: { keys: Object.keys(enforcements) } }), { status: 200 });
    }
    const enfMatch = /\/v1\/identity\/mfa\/login-enforcement\/(.+)$/.exec(u);
    if (enfMatch) {
      const name = decodeURIComponent(enfMatch[1]);
      return new Response(JSON.stringify({ data: enforcements[name] ?? {} }), { status: 200 });
    }
    if (u.endsWith('/v1/sys/auth')) {
      return new Response(JSON.stringify({ data: authMounts }), { status: 200 });
    }
    const polMatch = /\/v1\/sys\/policies\/acl\/(.+)$/.exec(u);
    if (polMatch) {
      const name = decodeURIComponent(polMatch[1]);
      return new Response(JSON.stringify({ data: { policy: policyBodies[name] ?? '' } }), { status: 200 });
    }
    throw new Error(`unexpected fake vault url: ${u} (${method})`);
  }) as typeof fetch;
}

const APPROLE_MOUNT = { 'approle/': { type: 'approle', accessor: 'auth_approle_1234' } };
const APPROLE_ENFORCEMENT = { 'audit-signing-enforcement': { auth_method_types: ['approle'] } };
const SIGN_ONLY_POLICY = 'path "transit/sign/audit-key" {\n  capabilities = ["update"]\n}\n';

test('CHARIOT::§9.8.1::2 — vault-transit custody check passes: MFA covers the mount, policy grants sign-only', async () => {
  const result = await checkVaultCustody('https://vault.internal:8200', 'tok', 'audit-key', {
    fetchImpl: fakeVaultFetch({
      policies: ['default', 'audit-signer'],
      tokenPath: 'auth/approle/login',
      enforcements: APPROLE_ENFORCEMENT,
      authMounts: APPROLE_MOUNT,
      policyBodies: { 'audit-signer': SIGN_ONLY_POLICY },
    }),
  });
  assert.equal(result.passed, true, result.reason);
});

test('CHARIOT::§9.8.1::2 — vault-transit custody check fails when no MFA login-enforcement is configured', async () => {
  const result = await checkVaultCustody('https://vault.internal:8200', 'tok', 'audit-key', {
    fetchImpl: fakeVaultFetch({
      policies: ['audit-signer'],
      tokenPath: 'auth/approle/login',
      enforcements: {},
      authMounts: APPROLE_MOUNT,
      policyBodies: { 'audit-signer': SIGN_ONLY_POLICY },
    }),
  });
  assert.equal(result.passed, false);
  assert.match(result.reason, /no MFA login-enforcement/);
});

test('CHARIOT::§9.8.1::2 — vault-transit custody check fails when the token carries only default/root policies', async () => {
  const result = await checkVaultCustody('https://vault.internal:8200', 'tok', 'audit-key', {
    fetchImpl: fakeVaultFetch({
      policies: ['default'],
      tokenPath: 'auth/approle/login',
      enforcements: APPROLE_ENFORCEMENT,
      authMounts: APPROLE_MOUNT,
    }),
  });
  assert.equal(result.passed, false);
  assert.match(result.reason, /only default\/root/);
});

test('CHARIOT::§9.8.1::2 — vault-transit custody check fails when NO policy grants sign on the configured key (closes the policy-body gap)', async () => {
  const result = await checkVaultCustody('https://vault.internal:8200', 'tok', 'audit-key', {
    fetchImpl: fakeVaultFetch({
      policies: ['default', 'unrelated-policy'],
      tokenPath: 'auth/approle/login',
      enforcements: APPROLE_ENFORCEMENT,
      authMounts: APPROLE_MOUNT,
      policyBodies: { 'unrelated-policy': 'path "secret/data/other" {\n  capabilities = ["read"]\n}\n' },
    }),
  });
  assert.equal(result.passed, false);
  assert.match(result.reason, /none of the token's scoped policies/);
});

test('CHARIOT::§9.8.1::2 — vault-transit custody check fails when a scoped policy ALSO grants delete on the key (broad key control)', async () => {
  const dangerousPolicy =
    'path "transit/sign/audit-key" {\n  capabilities = ["update"]\n}\n' +
    'path "transit/keys/audit-key" {\n  capabilities = ["read", "delete"]\n}\n';
  const result = await checkVaultCustody('https://vault.internal:8200', 'tok', 'audit-key', {
    fetchImpl: fakeVaultFetch({
      policies: ['default', 'audit-signer-plus-delete'],
      tokenPath: 'auth/approle/login',
      enforcements: APPROLE_ENFORCEMENT,
      authMounts: APPROLE_MOUNT,
      policyBodies: { 'audit-signer-plus-delete': dangerousPolicy },
    }),
  });
  assert.equal(result.passed, false);
  assert.match(result.reason, /broad key control/);
});

test('CHARIOT::§9.8.1::2 — vault-transit custody check fails when a scoped policy ALSO grants transit/export/* (key exfiltration)', async () => {
  const dangerousPolicy =
    'path "transit/sign/audit-key" {\n  capabilities = ["update"]\n}\n' +
    'path "transit/export/*" {\n  capabilities = ["read"]\n}\n';
  const result = await checkVaultCustody('https://vault.internal:8200', 'tok', 'audit-key', {
    fetchImpl: fakeVaultFetch({
      policies: ['default', 'audit-signer-plus-export'],
      tokenPath: 'auth/approle/login',
      enforcements: APPROLE_ENFORCEMENT,
      authMounts: APPROLE_MOUNT,
      policyBodies: { 'audit-signer-plus-export': dangerousPolicy },
    }),
  });
  assert.equal(result.passed, false);
  assert.match(result.reason, /broad key control/);
});

test('CHARIOT::§9.8.1::2 — vault-transit custody check fails when MFA enforcement exists but does not cover the token\'s auth mount', async () => {
  const result = await checkVaultCustody('https://vault.internal:8200', 'tok', 'audit-key', {
    fetchImpl: fakeVaultFetch({
      policies: ['default', 'audit-signer'],
      tokenPath: 'auth/approle/login',
      enforcements: { 'userpass-enforcement': { auth_method_types: ['userpass'] } }, // covers a DIFFERENT mount type
      authMounts: APPROLE_MOUNT,
      policyBodies: { 'audit-signer': SIGN_ONLY_POLICY },
    }),
  });
  assert.equal(result.passed, false);
  assert.match(result.reason, /none cover the signing token's auth mount/);
});

// ── 7-9: sealed-store ────────────────────────────────────────────────────

test('CHARIOT::§9.8.1::2 — sealed-store custody check passes (not checkable) outside enterprise mode', () => {
  withEnv({ CHARIOT_ENTERPRISE: undefined, CHARIOT_AUDIT_CUSTODY_ATTESTED: undefined }, () => {
    const result = checkSealedStoreCustody();
    assert.equal(result.passed, true);
    assert.equal(result.checkable, false);
  });
});

test('CHARIOT::§9.8.1::2 — sealed-store custody check fails in enterprise mode without an explicit attestation', () => {
  withEnv({ CHARIOT_ENTERPRISE: '1', CHARIOT_AUDIT_CUSTODY_ATTESTED: undefined }, () => {
    const result = checkSealedStoreCustody();
    assert.equal(result.passed, false);
    assert.equal(result.checkable, false);
  });
});

test('CHARIOT::§9.8.1::2 — sealed-store custody check passes in enterprise mode WITH CHARIOT_AUDIT_CUSTODY_ATTESTED=1 (still not checkable)', () => {
  withEnv({ CHARIOT_ENTERPRISE: '1', CHARIOT_AUDIT_CUSTODY_ATTESTED: '1' }, () => {
    const result = checkSealedStoreCustody();
    assert.equal(result.passed, true);
    assert.equal(result.checkable, false);
  });
});
