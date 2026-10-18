/**
 * Happy-path test for the signed export (C4AMD §8::8): events captured to
 * the LOCAL store are exported as a redacted, Ed25519-signed bundle whose
 * signature verifies against the signer's public key. The vault-transit
 * signer is driven through its injected fetch (no network, no key on disk).
 *
 * Run (after tsc): node --test dist/cli/telemetry.export.test.js
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as edSign, verify as edVerify } from 'node:crypto';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const tmp = mkdtempSync(join(tmpdir(), 'chariot-telemetry-export-'));
process.env.EPIC_AI_DIR_OVERRIDE = tmp;
process.env.HOME = tmp;
process.env.CHARIOT_AUDIT_VAULT_ADDR = 'https://vault.invalid';
process.env.CHARIOT_AUDIT_VAULT_TOKEN = 'test-token';
process.env.CHARIOT_AUDIT_VAULT_KEY_NAME = 'telemetry-test';
delete process.env.CHARIOT_ENTERPRISE;

const { setConsent } = await import('../iam/services/telemetry-consent.js');
const { captureEvent } = await import('../observability/operational-telemetry/capture.js');
const { exportToFile, EXPORT_ARTIFACT_TYPE } = await import('../observability/operational-telemetry/export.js');
const { canonicalStringify } = await import('../util/canonical-json.js');

after(() => rmSync(tmp, { recursive: true, force: true }));

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const rawPublic = (publicKey.export({ format: 'der', type: 'spki' }) as Buffer).subarray(-32);

function vaultFetch(): typeof fetch {
  return (async (url: string, init?: { body?: string }) => {
    const u = String(url);
    if (u.endsWith('/v1/transit/keys/telemetry-test')) {
      return new Response(
        JSON.stringify({ data: { type: 'ed25519', latest_version: 1, keys: { '1': { public_key: rawPublic.toString('base64') } } } }),
        { status: 200 },
      );
    }
    if (u.endsWith('/v1/transit/sign/telemetry-test')) {
      const input = Buffer.from((JSON.parse(init?.body ?? '{}') as { input: string }).input, 'base64');
      const sig = edSign(null, input, privateKey);
      return new Response(JSON.stringify({ data: { signature: `vault:v1:${sig.toString('base64')}` } }), { status: 200 });
    }
    return new Response('{}', { status: 404 }); // lookup-self etc. is best-effort
  }) as unknown as typeof fetch;
}

test('a signed export of locally stored events verifies, carries only the nine fields, and is a distinct artifact type', async () => {
  await setConsent('exp-t', true, 'ops', { statement: 'yes' });
  for (const tool of ['a.one', 'a.two']) {
    await captureEvent({
      tenantId: 'exp-t', canonicalToolId: tool, outcome: 'success', latencyMs: 3, failureStage: null, occurredAt: new Date('2026-10-12T09:15:00Z'),
    });
  }
  const dest = join(tmp, 'out', 'telemetry.json');
  const signed = await exportToFile('exp-t', dest, { backend: 'vault-transit', deps: { fetchImpl: vaultFetch() } });

  assert.strictEqual(signed.bundle.artifactType, EXPORT_ARTIFACT_TYPE);
  assert.strictEqual(signed.bundle.events.length, 2);
  for (const e of signed.bundle.events) {
    assert.deepStrictEqual(Object.keys(e).sort(), [
      'canonicalToolId', 'catalogEpoch', 'failureStage', 'hourBucket', 'latencyMs', 'outcome', 'platform', 'productVersion', 'tenantId',
    ]);
  }
  const onDisk = JSON.parse(readFileSync(dest, 'utf8')) as typeof signed;
  const ok = edVerify(null, Buffer.from(canonicalStringify(onDisk.bundle), 'utf8'), publicKey, Buffer.from(onDisk.signature.sig, 'base64'));
  assert.strictEqual(ok, true, 'Ed25519 signature over the canonical bundle verifies');
  assert.strictEqual(onDisk.signature.algorithm, 'ed25519');
});
