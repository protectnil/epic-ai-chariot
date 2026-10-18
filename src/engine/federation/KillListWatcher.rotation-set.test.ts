/**
 * CHARIOT::§5.1::9 applied to the kill list: the watcher's default trust
 * root is the whole compiled-in `CHARIOT_CATALOG_PUBLIC_KEYS` rotation set
 * (module header of `chariot-catalog-public.ts`: "Internal verification
 * walks `CHARIOT_CATALOG_PUBLIC_KEYS`"), so a publisher key rotation never
 * strands a self-hosted kill list on the previous key.
 *
 * `verifyKillListSignature` is exercised with throwaway Ed25519 key pairs
 * standing in for a two-entry rotation set: a body signed by EITHER entry
 * is accepted and the matched id is reported; a body signed by a key
 * outside the set, or a tampered body, is refused. The watcher itself is
 * then constructed without `publicKeyPem` and shown to refuse a list
 * signed by a key outside the compiled-in set (it cannot be shown to
 * accept one here: the production private keys are not available to
 * tests, by design).
 *
 * Run (after tsc): node --test dist/engine/federation/KillListWatcher.rotation-set.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { KillListWatcher, verifyKillListSignature } from './KillListWatcher.js';
import type { FederationManager } from './FederationManager.js';

function keyPair(): { pem: string; sign: (body: Buffer) => string } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    pem: publicKey.export({ type: 'spki', format: 'pem' }) as string,
    sign: (body) => cryptoSign(null, body, privateKey).toString('base64'),
  };
}

const first = keyPair();
const second = keyPair();
const outsider = keyPair();
const rotation = [
  { id: 'rot-first', pem: first.pem },
  { id: 'rot-second', pem: second.pem },
];
const body = Buffer.from(JSON.stringify({ version: '1', generatedAt: '2026-09-05T00:00:00Z', entries: [{ adapter_id: 'adapter-a' }] }));

test('a body signed by the first rotation entry is accepted and attributed to it', () => {
  assert.deepEqual(verifyKillListSignature(body, first.sign(body), rotation), {
    valid: true,
    keyId: 'rot-first',
  });
});

test('a body signed by the second rotation entry is accepted and attributed to it', () => {
  assert.deepEqual(verifyKillListSignature(body, second.sign(body), rotation), {
    valid: true,
    keyId: 'rot-second',
  });
});

test('a body signed by a key outside the rotation set is refused', () => {
  assert.deepEqual(verifyKillListSignature(body, outsider.sign(body), rotation), {
    valid: false,
    keyId: null,
  });
});

test('a tampered body is refused even when signed by a rotation entry', () => {
  const sig = first.sign(body);
  const tampered = Buffer.from(body);
  tampered[tampered.length - 3] ^= 0x01;
  assert.deepEqual(verifyKillListSignature(tampered, sig, rotation), { valid: false, keyId: null });
});

test('an empty accepted set refuses everything', () => {
  assert.deepEqual(verifyKillListSignature(body, first.sign(body), []), { valid: false, keyId: null });
});

test('the watcher with no publicKeyPem refuses a list signed outside the compiled-in rotation set', async () => {
  const unloaded: string[] = [];
  const federation = {
    serverNames: () => ['adapter-a'],
    unloadAdapter: async (id: string) => {
      unloaded.push(id);
      return { success: true, reason: 'kill_list', quiescent: true, inFlightAtClose: 0, durationMs: 1 };
    },
  } as unknown as FederationManager;
  const listBody = body;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async () =>
    new Response(listBody, {
      status: 200,
      headers: { 'kill-list-signature': outsider.sign(listBody) },
    })) as typeof fetch;
  try {
    const watcher = new KillListWatcher({
      federation,
      url: 'https://kill-list.invalid/list.json',
      intervalMs: 60_000,
    });
    watcher.start();
    await new Promise((resolve) => setTimeout(resolve, 50));
    watcher.stop();
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.deepEqual(unloaded, []);
});

test('the watcher with an explicit publicKeyPem accepts a list signed by that key only', async () => {
  const unloaded: string[] = [];
  const federation = {
    serverNames: () => ['adapter-a'],
    unloadAdapter: async (id: string) => {
      unloaded.push(id);
      return { success: true, reason: 'kill_list', quiescent: true, inFlightAtClose: 0, durationMs: 1 };
    },
  } as unknown as FederationManager;
  const listBody = body;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async () =>
    new Response(listBody, {
      status: 200,
      headers: { 'kill-list-signature': outsider.sign(listBody) },
    })) as typeof fetch;
  try {
    const watcher = new KillListWatcher({
      federation,
      url: 'https://kill-list.invalid/list.json',
      intervalMs: 60_000,
      publicKeyPem: outsider.pem,
    });
    watcher.start();
    await new Promise((resolve) => setTimeout(resolve, 50));
    watcher.stop();
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.deepEqual(unloaded, ['adapter-a']);
});
