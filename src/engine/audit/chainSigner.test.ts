/**
 * @epicai/chariot — Adversarial eval for CHARIOT::§9.8.1 (chainSigner.ts)
 *
 * Failure classes enumerated from CHARIOT-SPEC.md §9.8.1 (docs/spec/CHARIOT-SPEC.md:899-906):
 *   1. gate finding F1 (2026-09-04): there is NO plaintext `env`
 *      backend any more, in ANY mode — CHARIOT §9.8.1::1's "Plaintext key
 *      material MUST NOT be stored on the application host filesystem" is
 *      unconditional. `CHARIOT_AUDIT_SIGNER_BACKEND=env` is rejected as an
 *      unknown backend; the default (unset) backend is `sealed-store`;
 *      setting only the now-inert `CHARIOT_AUDIT_SIGNING_KEY` with no
 *      custody backend provisioned fails closed, never silently signs.
 *   3. sealed-store round trip: signature verifies AND the on-disk artifact
 *      never contains the private-key PEM bytes (no plaintext on host fs).
 *   4. unknown backend name rejected with an actionable error.
 *   5. kms backend: TRUE remote signing (GetPublicKey + Sign, private key
 *      never leaves KMS) via injected fake transport (no network); a
 *      non-ECC_NIST_EDWARDS25519 KeySpec is refused.
 *   6. vault-transit backend: sign via injected fake transport (no network),
 *      non-ed25519 Vault key type rejected.
 *   7. multi-key verification: unknown kid → false (never throws); known kid → true.
 *
 * Run after `tsc`: node --test dist/engine/audit/chainSigner.test.js
 * Registered in scripts/run-all-tests.mjs.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as edSign } from 'node:crypto';
import { mkdtempSync, rmSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  createChainSigner,
  computeKid,
  sealSigningKey,
  resolveVerifyKeys,
  verifyWithKeySet,
} from './chainSigner.js';

function withEnv(vars: Record<string, string | undefined>, fn: () => Promise<void> | void): Promise<void> {
  const prev: Record<string, string | undefined> = {};
  for (const k of Object.keys(vars)) prev[k] = process.env[k];
  for (const [k, v] of Object.entries(vars)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  return Promise.resolve(fn()).finally(() => {
    for (const [k, v] of Object.entries(prev)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  });
}

function genEd25519(): { privateKeyPem: string; publicKeyPem: string } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }) as string,
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }) as string,
  };
}

// ── 1: no plaintext env backend, in ANY mode (gate finding F1) ────────

test('CHARIOT::§9.8.1::1 — CHARIOT_AUDIT_SIGNER_BACKEND=env is rejected as an unknown backend (removed entirely)', async () => {
  const { privateKeyPem } = genEd25519();
  await withEnv(
    { CHARIOT_ENTERPRISE: undefined, CHARIOT_AUDIT_SIGNER_BACKEND: 'env', CHARIOT_AUDIT_SIGNING_KEY: privateKeyPem },
    async () => {
      await assert.rejects(() => createChainSigner(), /Unknown CHARIOT_AUDIT_SIGNER_BACKEND 'env'/);
    },
  );
});

test('CHARIOT::§9.8.1::1 — CHARIOT_AUDIT_SIGNER_BACKEND=env is STILL rejected when CHARIOT_ENTERPRISE=1', async () => {
  const { privateKeyPem } = genEd25519();
  await withEnv(
    { CHARIOT_ENTERPRISE: '1', CHARIOT_AUDIT_SIGNER_BACKEND: 'env', CHARIOT_AUDIT_SIGNING_KEY: privateKeyPem },
    async () => {
      await assert.rejects(() => createChainSigner(), /Unknown CHARIOT_AUDIT_SIGNER_BACKEND 'env'/);
    },
  );
});

test('CHARIOT::§9.8.1::1 — default backend (CHARIOT_AUDIT_SIGNER_BACKEND unset) is sealed-store, not plaintext', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-default-backend-'));
  try {
    await withEnv(
      { CHARIOT_AUDIT_SIGNER_BACKEND: undefined, ENTERPRISE_MASTER_KEY: Buffer.alloc(32, 1).toString('base64') },
      async () => {
        const { privateKeyPem, publicKeyPem } = genEd25519();
        sealSigningKey(dir, privateKeyPem);
        const signer = await createChainSigner({ packageRoot: dir });
        assert.equal(signer.backend, 'sealed-store');
        const info = await signer.getKeyInfo();
        assert.equal(info.publicKeyPem, publicKeyPem);
      },
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('CHARIOT::§9.8.1::1 — CHARIOT_AUDIT_SIGNING_KEY alone (no custody backend provisioned) never silently signs — fails closed', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-no-custody-'));
  try {
    const { privateKeyPem } = genEd25519();
    await withEnv(
      { CHARIOT_AUDIT_SIGNER_BACKEND: undefined, CHARIOT_AUDIT_SIGNING_KEY: privateKeyPem },
      async () => {
        // No sealed-store key was ever provisioned under `dir` — the
        // (now-inert) CHARIOT_AUDIT_SIGNING_KEY must not be consulted as a
        // fallback signing source.
        await assert.rejects(
          () => createChainSigner({ packageRoot: dir }),
          /no sealed audit signing key found/,
        );
      },
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── 3: sealed-store round trip, no plaintext on disk ────────────────────────

test('CHARIOT::§9.8.1::1 — sealed-store round trip signs correctly and stores NO plaintext key on disk', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-sealed-'));
  try {
    await withEnv({ ENTERPRISE_MASTER_KEY: Buffer.alloc(32, 7).toString('base64') }, async () => {
      const { privateKeyPem, publicKeyPem } = genEd25519();
      const { kid } = sealSigningKey(dir, privateKeyPem);

      // The on-disk artifact must NOT contain the PEM bytes anywhere.
      const files = readdirSync(join(dir, 'audit'));
      assert.ok(files.some((f) => f === `signing-key.${kid}.sealed.json`));
      for (const f of files) {
        const content = readFileSync(join(dir, 'audit', f), 'utf-8');
        assert.ok(!content.includes('PRIVATE KEY'), `${f} must not contain plaintext private key material`);
      }

      const signer = await createChainSigner({ backend: 'sealed-store', packageRoot: dir });
      assert.equal(signer.backend, 'sealed-store');
      const info = await signer.getKeyInfo();
      assert.equal(info.kid, kid);
      assert.equal(info.publicKeyPem, publicKeyPem);

      const payload = Buffer.from('sealed-store-payload');
      const sig = await signer.sign(payload);
      const { verify } = await import('node:crypto');
      assert.ok(verify(null, payload, publicKeyPem, sig));
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('CHARIOT::§9.8.1::1 — sealed-store with no provisioned key fails with an actionable error', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-sealed-empty-'));
  try {
    await assert.rejects(
      () => createChainSigner({ backend: 'sealed-store', packageRoot: dir }),
      /no sealed audit signing key found/,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── 4: unknown backend ───────────────────────────────────────────────────────

test('CHARIOT::§9.8.1::1 — unknown backend name rejected', async () => {
  await assert.rejects(
    () => createChainSigner({ backend: 'carrier-pigeon' as never }),
    /Unknown CHARIOT_AUDIT_SIGNER_BACKEND/,
  );
});

// ── 5: kms backend — TRUE remote signing (GetPublicKey + Sign), fake transport, no network ──

interface FakeKmsCmd {
  __type: 'GetPublicKey' | 'Sign';
  input: Record<string, unknown>;
}
const FakeGetPublicKeyCommand = class implements FakeKmsCmd {
  __type = 'GetPublicKey' as const;
  constructor(public input: { KeyId: string }) {}
} as unknown as new (input: { KeyId: string }) => unknown;
const FakeSignCommand = class implements FakeKmsCmd {
  __type = 'Sign' as const;
  constructor(public input: { KeyId: string; Message: Uint8Array; MessageType: string; SigningAlgorithm: string }) {}
} as unknown as new (input: {
  KeyId: string;
  Message: Uint8Array;
  MessageType: string;
  SigningAlgorithm: string;
}) => unknown;

test('CHARIOT::§9.8.1::1 — kms backend is TRUE remote signing (GetPublicKey + Sign) via injected fake transport (no network); private key never leaves KMS', async () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;

  await withEnv({ CHARIOT_AUDIT_KMS_KEY_ID: 'arn:aws:kms:us-east-1:123:key/fake' }, async () => {
    const signer = await createChainSigner({
      backend: 'kms',
      deps: {
        kmsClientFactory: () => ({
          send: async (cmd: unknown) => {
            const c = cmd as FakeKmsCmd;
            if (c.__type === 'GetPublicKey') {
              return { PublicKey: publicKeyDer, KeySpec: 'ECC_NIST_EDWARDS25519' };
            }
            if (c.__type === 'Sign') {
              assert.equal(c.input.MessageType, 'RAW', 'MessageType must be RAW (not DIGEST — no double-hash)');
              assert.equal(c.input.SigningAlgorithm, 'ED25519_SHA_512');
              return { Signature: edSign(null, c.input.Message as Uint8Array, privateKey) };
            }
            throw new Error(`unexpected fake KMS command: ${JSON.stringify(c)}`);
          },
        }),
        kmsGetPublicKeyCommandCtor: FakeGetPublicKeyCommand,
        kmsSignCommandCtor: FakeSignCommand,
      },
    });
    assert.equal(signer.backend, 'kms');
    const info = await signer.getKeyInfo();
    assert.equal(info.kid, computeKid(publicKeyPem));
    assert.equal(info.publicKeyPem, publicKeyPem);
    const payload = Buffer.from('kms-remote-sign-payload');
    const sig = await signer.sign(payload);
    const { verify } = await import('node:crypto');
    assert.ok(verify(null, payload, publicKeyPem, sig));
  });
});

test('CHARIOT::§9.8.1::1 — kms backend refuses a KMS key whose KeySpec is not ECC_NIST_EDWARDS25519', async () => {
  await withEnv({ CHARIOT_AUDIT_KMS_KEY_ID: 'arn:aws:kms:us-east-1:123:key/fake-rsa' }, async () => {
    await assert.rejects(
      () =>
        createChainSigner({
          backend: 'kms',
          deps: {
            kmsClientFactory: () => ({
              send: async () => ({ PublicKey: Buffer.from('irrelevant'), KeySpec: 'RSA_2048' }),
            }),
            kmsGetPublicKeyCommandCtor: FakeGetPublicKeyCommand,
            kmsSignCommandCtor: FakeSignCommand,
          },
        }),
      /KeySpec 'RSA_2048'.*requires an Ed25519 KMS key \(KeySpec=ECC_NIST_EDWARDS25519\)/,
    );
  });
});

test('CHARIOT::§9.8.1::1 — kms backend requires CHARIOT_AUDIT_KMS_KEY_ID', async () => {
  await withEnv({ CHARIOT_AUDIT_KMS_KEY_ID: undefined }, async () => {
    await assert.rejects(() => createChainSigner({ backend: 'kms' }), /requires CHARIOT_AUDIT_KMS_KEY_ID/);
  });
});

// ── 6: vault-transit backend, fake transport, no network ────────────────────

test('CHARIOT::§9.8.1::1 — vault-transit backend signs via injected fake fetch (no network)', async () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const rawPub = (publicKey.export({ type: 'spki', format: 'der' }) as Buffer).subarray(-32);
  const payloadToSign = Buffer.from('vault-transit-payload');
  const realSig = edSign(null, payloadToSign, privateKey);

  const fakeFetch = (async (url: string | URL, init?: RequestInit) => {
    const u = String(url);
    if (u.endsWith('/v1/transit/keys/audit-signing-key')) {
      return new Response(
        JSON.stringify({ data: { type: 'ed25519', latest_version: 3, keys: { '3': { public_key: rawPub.toString('base64') } } } }),
        { status: 200 },
      );
    }
    if (u.endsWith('/v1/auth/token/lookup-self')) {
      return new Response(JSON.stringify({ data: { display_name: 'chariot-audit-svc' } }), { status: 200 });
    }
    if (u.endsWith('/v1/transit/sign/audit-signing-key')) {
      const body = JSON.parse(String(init?.body)) as { input: string; key_version: number };
      assert.equal(Buffer.from(body.input, 'base64').toString('utf-8'), payloadToSign.toString('utf-8'));
      assert.equal(body.key_version, 3);
      return new Response(JSON.stringify({ data: { signature: `vault:v3:${realSig.toString('base64')}` } }), { status: 200 });
    }
    throw new Error(`unexpected fake fetch url: ${u}`);
  }) as typeof fetch;

  await withEnv(
    {
      CHARIOT_AUDIT_VAULT_ADDR: 'https://vault.internal:8200',
      CHARIOT_AUDIT_VAULT_TOKEN: 'fake-token',
      CHARIOT_AUDIT_VAULT_KEY_NAME: 'audit-signing-key',
    },
    async () => {
      const signer = await createChainSigner({ backend: 'vault-transit', deps: { fetchImpl: fakeFetch } });
      assert.equal(signer.backend, 'vault-transit');
      const info = await signer.getKeyInfo();
      assert.equal(info.kid, computeKid(publicKey));
      const sig = await signer.sign(payloadToSign);
      assert.equal(sig.toString('base64'), realSig.toString('base64'));
    },
  );
});

test('CHARIOT::§9.8.1::1 — vault-transit backend rejects a non-ed25519 Vault key type', async () => {
  const fakeFetch = (async () => new Response(JSON.stringify({ data: { type: 'ecdsa-p256' } }), { status: 200 })) as typeof fetch;
  await withEnv(
    {
      CHARIOT_AUDIT_VAULT_ADDR: 'https://vault.internal:8200',
      CHARIOT_AUDIT_VAULT_TOKEN: 'fake-token',
      CHARIOT_AUDIT_VAULT_KEY_NAME: 'audit-signing-key',
    },
    async () => {
      await assert.rejects(
        () => createChainSigner({ backend: 'vault-transit', deps: { fetchImpl: fakeFetch } }),
        /must be type ed25519/,
      );
    },
  );
});

// ── 7: multi-key verification (CH-03 pattern) ───────────────────────────────

test('CHARIOT::§9.8.1::3 — multi-key verify: known kid passes, unknown kid fails, never throws', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-verifykeys-'));
  try {
    const a = genEd25519();
    const b = genEd25519();
    await withEnv({ CHARIOT_AUDIT_VERIFY_KEYS: JSON.stringify({ [computeKid(a.publicKeyPem)]: a.publicKeyPem }) }, async () => {
      const verifyKeys = resolveVerifyKeys(dir);
      const payload = Buffer.from('multi-key-payload');
      const { createPrivateKey } = await import('node:crypto');
      const sigA = edSign(null, payload, createPrivateKey(a.privateKeyPem));
      const sigB = edSign(null, payload, createPrivateKey(b.privateKeyPem));

      assert.equal(verifyWithKeySet(payload, sigA, computeKid(a.publicKeyPem), verifyKeys), true);
      // b's kid was never registered — must fail, not throw.
      assert.equal(verifyWithKeySet(payload, sigB, computeKid(b.publicKeyPem), verifyKeys), false);
      assert.equal(verifyWithKeySet(payload, sigA, 'totally-unknown-kid', verifyKeys), false);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('CHARIOT::§9.8.1::3 — resolveVerifyKeys retains legacy single key, CHARIOT_AUDIT_VERIFY_KEYS, AND the persistent store', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-verifykeys-merge-'));
  try {
    const legacy = genEd25519();
    const envRotated = genEd25519();
    const { appendVerifyKey } = await import('./verifyKeyStore.js');
    const persisted = genEd25519();
    appendVerifyKey(dir, computeKid(persisted.publicKeyPem), persisted.publicKeyPem);

    await withEnv(
      {
        CHARIOT_AUDIT_SIGNING_KEY: legacy.privateKeyPem,
        CHARIOT_AUDIT_VERIFY_KEYS: JSON.stringify({ [computeKid(envRotated.publicKeyPem)]: envRotated.publicKeyPem }),
      },
      async () => {
        const verifyKeys = resolveVerifyKeys(dir);
        assert.ok(verifyKeys.has(computeKid(legacy.publicKeyPem)), 'legacy single-var key must merge');
        assert.ok(verifyKeys.has(computeKid(envRotated.publicKeyPem)), 'CHARIOT_AUDIT_VERIFY_KEYS entry must merge');
        assert.ok(verifyKeys.has(computeKid(persisted.publicKeyPem)), 'persistent verify-key store entry must merge');
      },
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
