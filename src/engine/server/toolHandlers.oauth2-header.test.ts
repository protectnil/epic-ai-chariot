/**
 * Prove-on-revert for rulings item 196: the ordinary MCP dispatch path's
 * Authorization-header construction (toolHandlers.ts, Case 4 streamable-http
 * dispatch, "Phase R.3: attach Authorization header at construction ...")
 * previously sent NO header for `authScheme: 'oauth2'` ("'oauth2' deferred —
 * bundle entries requiring oauth2 should declare authProvider externally").
 *
 * §10.5's vendor OAuth refresh job stores the access token in the SAME
 * `apiKey` vault field a plain api-key credential uses (credentials.ts:313,
 * `apiKey: vendorResponse.access_token`), and `credential-loader.ts:49-72`
 * maps that `apiKey` onto the adapter's declared `authEnvKey` exactly like
 * any other credential — so `state.credentials[authEnvKey]` IS the access
 * token for an oauth2 row by dispatch time. 'oauth2' now takes the SAME
 * branch as 'bearer': `Authorization: Bearer <token>`.
 *
 * Real in-process MCP server fixture (StreamableHTTPServerTransport +
 * McpServer over an actual node:http socket) reused verbatim from the
 * pattern in CustomerAuthOverlay.test.ts's
 * "streamable-HTTP: Authorization header present on every request, tools/list
 * issued once" test — the same request-header-capturing `createServer`
 * handler wrapping `transport.handleRequest`.
 *
 * Run (after tsc): node --test dist/engine/server/toolHandlers.oauth2-header.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';

import { handleCall } from './toolHandlers.js';
import type { CallContext } from './toolHandlers.js';
import type { ChariotState, AdapterEntry } from './ChariotState.js';

function makeStateWithHttpAdapter(
  adapterId: string,
  url: string,
  authScheme: 'bearer' | 'oauth2' | undefined,
  credentialValue: string,
): ChariotState {
  const adapter = {
    id: adapterId,
    name: adapterId,
    type: 'mcp',
    category: 'test',
    mcp: {
      transport: 'streamable-http',
      url,
      authEnvKey: 'TEST_TOKEN',
      ...(authScheme ? { authScheme } : {}),
      tools: [{ name: 'echo', inputSchema: { type: 'object', properties: {} } }],
    },
  } as unknown as AdapterEntry;
  return {
    allAdapters: [adapter],
    adapterById: new Map([[adapterId, adapter]]),
    configuredAdapterIds: new Set([adapterId]),
    credentials: { TEST_TOKEN: credentialValue },
    fullCatalogFilter: { select: async () => [] },
    toolPreFilter: { select: async () => [] },
    getConfiguredAdapters: () => [adapter],
    loadedAt: new Date(),
  } as unknown as ChariotState;
}

/** Real MCP server over a real socket; returns the capturing server plus its URL. */
async function startFixtureServer(): Promise<{ url: string; seenHeaders: string[]; close: () => void }> {
  const seenHeaders: string[] = [];
  const server = new McpServer({ name: 'oauth2-header-fixture', version: '1.0.0' });
  server.tool('echo', { text: z.string().optional() }, async (args) => ({
    content: [{ type: 'text' as const, text: args.text ?? 'ok' }],
  }));
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: () => randomUUID() });
  await server.connect(transport);
  const httpServer = createServer((req, res) => {
    const auth = req.headers['authorization'];
    if (typeof auth === 'string') seenHeaders.push(auth);
    void (async () => {
      try {
        await transport.handleRequest(req, res);
      } catch {
        if (!res.headersSent) { res.writeHead(500); res.end('error'); }
      }
    })();
  });
  await new Promise<void>((resolve) => httpServer.listen(0, '127.0.0.1', resolve));
  const addr = httpServer.address();
  if (!addr || typeof addr !== 'object') throw new Error('failed to bind fixture server');
  return { url: `http://127.0.0.1:${addr.port}/mcp`, seenHeaders, close: () => httpServer.close() };
}

test('rulings 196: an oauth2 adapter dispatches with an Authorization: Bearer header (previously sent none)', async () => {
  const fixture = await startFixtureServer();
  try {
    const state = makeStateWithHttpAdapter('oauth2-adapter', fixture.url, 'oauth2', 'oauth-access-token-xyz');
    const ctx: CallContext = { localMode: true };
    const result = await handleCall({ adapter: 'oauth2-adapter', tool: 'echo', args: { text: 'hi' } }, state, ctx);

    assert.equal(result.isError, false, `expected a successful dispatch, got: ${result.content}`);
    assert.ok(fixture.seenHeaders.length > 0, 'expected at least one request to reach the fixture server');
    assert.ok(
      fixture.seenHeaders.every((h) => h === 'Bearer oauth-access-token-xyz'),
      `every request must carry the Bearer header, saw: ${JSON.stringify(fixture.seenHeaders)}`,
    );
  } finally {
    fixture.close();
  }
});

test('rulings 196: a bearer adapter is unchanged — still dispatches with the same Authorization: Bearer header', async () => {
  const fixture = await startFixtureServer();
  try {
    const state = makeStateWithHttpAdapter('bearer-adapter', fixture.url, 'bearer', 'plain-bearer-token-abc');
    const ctx: CallContext = { localMode: true };
    const result = await handleCall({ adapter: 'bearer-adapter', tool: 'echo', args: { text: 'hi' } }, state, ctx);

    assert.equal(result.isError, false, `expected a successful dispatch, got: ${result.content}`);
    assert.ok(fixture.seenHeaders.length > 0);
    assert.ok(
      fixture.seenHeaders.every((h) => h === 'Bearer plain-bearer-token-abc'),
      `bearer behavior must be unchanged, saw: ${JSON.stringify(fixture.seenHeaders)}`,
    );
  } finally {
    fixture.close();
  }
});

test('rulings 196: the default scheme (authScheme absent) is still treated as bearer, unaffected by the oauth2 fix', async () => {
  const fixture = await startFixtureServer();
  try {
    const state = makeStateWithHttpAdapter('default-scheme-adapter', fixture.url, undefined, 'default-scheme-token');
    const ctx: CallContext = { localMode: true };
    const result = await handleCall({ adapter: 'default-scheme-adapter', tool: 'echo', args: { text: 'hi' } }, state, ctx);

    assert.equal(result.isError, false, `expected a successful dispatch, got: ${result.content}`);
    assert.ok(fixture.seenHeaders.length > 0, 'expected at least one request to reach the fixture server');
    assert.ok(
      fixture.seenHeaders.every((h) => h === 'Bearer default-scheme-token'),
      `saw: ${JSON.stringify(fixture.seenHeaders)}`,
    );
  } finally {
    fixture.close();
  }
});
