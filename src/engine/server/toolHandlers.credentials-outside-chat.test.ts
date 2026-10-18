/**
 * Credentials outside the chat — handleCall integration.
 *
 * With a prompter in scope (single-user local transport), an adapter missing
 * its required credential returns `credentials_pending` carrying the private
 * page URL and guidance that forbids pasting the secret; a declined prompt
 * returns `credentials_declined`; with NO prompter in scope (multi-tenant
 * HTTP) the new block is inert and no private page URL is ever produced.
 *
 * Run (after tsc): node --test dist/engine/server/toolHandlers.credentials-outside-chat.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { handleCall, credentialPrompterStorage } from './toolHandlers.js';
import type { ChariotState, AdapterEntry } from './ChariotState.js';
import type { CredentialPrompter } from '../credentials/ensureCredentials.js';

const KEY = 'OUTSIDECHAT_TEST_API_KEY';

function makeState(): ChariotState {
  const adapter = {
    id: 'outside-chat',
    name: 'Outside Chat',
    type: 'mcp',
    category: 'test',
    mcp: {
      transport: 'streamable-http',
      url: 'http://127.0.0.1:1/mcp',
      envKeys: [KEY],
      authEnvKey: KEY,
      tools: [{ name: 'echo', inputSchema: { type: 'object', properties: {} } }],
    },
  } as unknown as AdapterEntry;
  return {
    allAdapters: [adapter],
    adapterById: new Map([['outside-chat', adapter]]),
    configuredAdapterIds: new Set(['outside-chat']),
    credentials: {},
    fullCatalogFilter: { select: async () => [] },
    toolPreFilter: { select: async () => [] },
    getConfiguredAdapters: () => [adapter],
    loadedAt: new Date(),
  } as unknown as ChariotState;
}

const call = (state: ChariotState) =>
  handleCall({ adapter: 'outside-chat', tool: 'echo', args: {} }, state, { localMode: true });

test('pending: the result carries the private URL and forbids pasting the secret', async () => {
  delete process.env[KEY];
  const seen: unknown[] = [];
  const prompter: CredentialPrompter = async (req) => {
    seen.push(req);
    return { kind: 'pending', url: 'http://127.0.0.1:4242/c/tok' };
  };
  const r = await credentialPrompterStorage.run(prompter, () => call(makeState()));
  assert.equal(r.isError, true);
  const body = JSON.parse(r.content) as Record<string, unknown>;
  assert.equal(body.error, 'credentials_pending');
  assert.equal(body.privatePageUrl, 'http://127.0.0.1:4242/c/tok');
  assert.deepEqual(body.missing, [KEY]);
  assert.match(String(body.guidance), /Do not ask the user to paste the credential here/);
  assert.deepEqual(seen, [{ adapterId: 'outside-chat', adapterName: 'Outside Chat', keys: [KEY] }]);
});

test('declined: credentials_declined, and the guidance says not to retry', async () => {
  delete process.env[KEY];
  const r = await credentialPrompterStorage.run(async () => ({ kind: 'declined' }), () => call(makeState()));
  const body = JSON.parse(r.content) as Record<string, unknown>;
  assert.equal(body.error, 'credentials_declined');
  assert.match(String(body.guidance), /Do not retry/);
});

test('no prompter in scope: the block is inert and no private URL is produced', async () => {
  delete process.env[KEY];
  const r = await call(makeState());
  assert.ok(!r.content.includes('privatePageUrl'), r.content);
  assert.ok(!r.content.includes('credentials_declined'));
});

test('credential present (process environment): the prompter is never consulted', async () => {
  process.env[KEY] = 'have-it';
  try {
    let consulted = false;
    await credentialPrompterStorage.run(async () => { consulted = true; return { kind: 'declined' }; }, () => call(makeState()));
    assert.equal(consulted, false);
  } finally {
    delete process.env[KEY];
  }
});
