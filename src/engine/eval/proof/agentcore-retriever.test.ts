/**
 * Epic AI® Chariot — AgentCore Gateway competitor target unit tests
 * (CHARIOT-SPEC §4.5, §23 AWS-native coopetition)
 *
 * Derived from the fail-explicit contract this module states in its header:
 * "when CHARIOT_AGENTCORE_GATEWAY_URL or CHARIOT_AGENTCORE_BEARER_TOKEN is
 * unset, info.runnable is false and retrieve() THROWS a typed, actionable
 * error naming the missing env var" — the load-bearing case is that an
 * unconfigured target NEVER returns an empty/fabricated result.
 *
 * Run: node --test dist/engine/eval/proof/agentcore-retriever.test.js
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  AgentCoreGatewayRetriever,
  AgentCoreNotConfiguredError,
  AgentCoreGatewayError,
  parseSearchResult,
  splitAgentCoreToolId,
  readAgentCoreConfig,
  AGENTCORE_ENV,
} from './agentcore-retriever.js';

function withEnv<T>(vars: Record<string, string | undefined>, fn: () => T): T {
  const prior: Record<string, string | undefined> = {};
  for (const k of Object.keys(vars)) prior[k] = process.env[k];
  for (const [k, v] of Object.entries(vars)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  try {
    return fn();
  } finally {
    for (const [k, v] of Object.entries(prior)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

// ─── fail-explicit: unconfigured ────────────────────────────────────────────

test('readAgentCoreConfig reports both env vars missing when neither is set', () => {
  withEnv({ [AGENTCORE_ENV.GATEWAY_URL]: undefined, [AGENTCORE_ENV.BEARER_TOKEN]: undefined }, () => {
    const { missing, gatewayUrl, bearerToken } = readAgentCoreConfig();
    assert.deepEqual(missing.sort(), [AGENTCORE_ENV.BEARER_TOKEN, AGENTCORE_ENV.GATEWAY_URL].sort());
    assert.equal(gatewayUrl, undefined);
    assert.equal(bearerToken, undefined);
  });
});

test('readAgentCoreConfig reports only the token missing when the URL is set', () => {
  withEnv({ [AGENTCORE_ENV.GATEWAY_URL]: 'https://gw.example.amazonaws.com', [AGENTCORE_ENV.BEARER_TOKEN]: undefined }, () => {
    const { missing } = readAgentCoreConfig();
    assert.deepEqual(missing, [AGENTCORE_ENV.BEARER_TOKEN]);
  });
});

test('AgentCoreGatewayRetriever.info.runnable is false when unconfigured', () => {
  withEnv({ [AGENTCORE_ENV.GATEWAY_URL]: undefined, [AGENTCORE_ENV.BEARER_TOKEN]: undefined }, () => {
    const r = new AgentCoreGatewayRetriever();
    assert.equal(r.info.runnable, false);
    assert.equal(r.info.kind, 'competitor');
  });
});

test('AgentCoreGatewayRetriever.retrieve() THROWS AgentCoreNotConfiguredError when unconfigured — never returns [] silently', async () => {
  await withEnv({ [AGENTCORE_ENV.GATEWAY_URL]: undefined, [AGENTCORE_ENV.BEARER_TOKEN]: undefined }, async () => {
    const r = new AgentCoreGatewayRetriever();
    await assert.rejects(() => r.retrieve('find order details', 8), AgentCoreNotConfiguredError);
  });
});

test('AgentCoreNotConfiguredError message names the exact missing env var(s)', async () => {
  await withEnv({ [AGENTCORE_ENV.GATEWAY_URL]: undefined, [AGENTCORE_ENV.BEARER_TOKEN]: undefined }, async () => {
    const r = new AgentCoreGatewayRetriever();
    try {
      await r.retrieve('q', 8);
      assert.fail('expected retrieve() to throw');
    } catch (err) {
      assert.ok(err instanceof AgentCoreNotConfiguredError);
      assert.match((err as Error).message, new RegExp(AGENTCORE_ENV.GATEWAY_URL));
      assert.match((err as Error).message, new RegExp(AGENTCORE_ENV.BEARER_TOKEN));
    }
  });
});

// ─── fail-explicit: configured but the Gateway call itself fails ───────────

test('AgentCoreGatewayRetriever.retrieve() throws AgentCoreGatewayError on HTTP failure — never swallows the error', async () => {
  await withEnv(
    { [AGENTCORE_ENV.GATEWAY_URL]: 'https://gw.example.amazonaws.com', [AGENTCORE_ENV.BEARER_TOKEN]: 'tok' },
    async () => {
      const fetchImpl = (async () =>
        new Response('unauthorized', { status: 401, statusText: 'Unauthorized' })) as unknown as typeof fetch;
      const r = new AgentCoreGatewayRetriever({ fetchImpl });
      assert.equal(r.info.runnable, true);
      await assert.rejects(() => r.retrieve('q', 8), AgentCoreGatewayError);
    },
  );
});

test('AgentCoreGatewayRetriever.retrieve() throws AgentCoreGatewayError (with cause) when fetch itself rejects — never returns [] silently', async () => {
  await withEnv(
    { [AGENTCORE_ENV.GATEWAY_URL]: 'https://gw.example.amazonaws.com', [AGENTCORE_ENV.BEARER_TOKEN]: 'tok' },
    async () => {
      const networkError = new Error('getaddrinfo ENOTFOUND gw.example.amazonaws.com');
      const fetchImpl = (async () => {
        throw networkError;
      }) as unknown as typeof fetch;
      const r = new AgentCoreGatewayRetriever({ fetchImpl });
      let thrown: unknown;
      try {
        await r.retrieve('q', 8);
        assert.fail('expected retrieve() to throw, not resolve');
      } catch (err) {
        thrown = err;
      }
      assert.ok(thrown instanceof AgentCoreGatewayError);
      assert.equal((thrown as AgentCoreGatewayError).cause, networkError);
      assert.match((thrown as Error).message, /getaddrinfo ENOTFOUND/);
    },
  );
});

test('AgentCoreGatewayRetriever.retrieve() throws on a JSON-RPC error envelope', async () => {
  await withEnv(
    { [AGENTCORE_ENV.GATEWAY_URL]: 'https://gw.example.amazonaws.com', [AGENTCORE_ENV.BEARER_TOKEN]: 'tok' },
    async () => {
      const body = JSON.stringify({ jsonrpc: '2.0', id: '1', error: { code: -32600, message: 'bad request' } });
      const fetchImpl = (async () => new Response(body, { status: 200 })) as unknown as typeof fetch;
      const r = new AgentCoreGatewayRetriever({ fetchImpl });
      await assert.rejects(() => r.retrieve('q', 8), AgentCoreGatewayError);
    },
  );
});

// ─── happy path: configured + a well-formed Gateway response ───────────────

test('AgentCoreGatewayRetriever.retrieve() parses a structuredContent tool array and caps at k', async () => {
  await withEnv(
    { [AGENTCORE_ENV.GATEWAY_URL]: 'https://gw.example.amazonaws.com', [AGENTCORE_ENV.BEARER_TOKEN]: 'tok' },
    async () => {
      const body = JSON.stringify({
        jsonrpc: '2.0',
        id: '1',
        result: {
          structuredContent: [
            { name: 'stripe-target___create_refund' },
            { name: 'stripe-target___list_customers' },
            { name: 'okta-target___list_users' },
          ],
        },
      });
      let capturedUrl = '';
      let capturedBody = '';
      const fetchImpl = (async (url: unknown, init?: RequestInit) => {
        capturedUrl = String(url);
        capturedBody = String(init?.body ?? '');
        return new Response(body, { status: 200 });
      }) as unknown as typeof fetch;
      const r = new AgentCoreGatewayRetriever({ fetchImpl });
      const results = await r.retrieve('process a refund', 2);
      assert.equal(results.length, 2);
      assert.deepEqual(results[0], { id: 'stripe-target:create_refund', server: 'stripe-target', name: 'create_refund' });
      assert.equal(capturedUrl, 'https://gw.example.amazonaws.com/mcp');
      const parsed = JSON.parse(capturedBody);
      assert.equal(parsed.params.name, 'x_amz_bedrock_agentcore_search');
      assert.equal(parsed.params.arguments.query, 'process a refund');
    },
  );
});

test('AgentCoreGatewayRetriever.retrieve() parses a content[].text JSON tool array', async () => {
  await withEnv(
    { [AGENTCORE_ENV.GATEWAY_URL]: 'https://gw.example.amazonaws.com/', [AGENTCORE_ENV.BEARER_TOKEN]: 'tok' },
    async () => {
      const toolsJson = JSON.stringify([{ name: 'okta___list_users' }]);
      const body = JSON.stringify({
        jsonrpc: '2.0',
        id: '1',
        result: { content: [{ type: 'text', text: toolsJson }] },
      });
      const fetchImpl = (async () => new Response(body, { status: 200 })) as unknown as typeof fetch;
      const r = new AgentCoreGatewayRetriever({ fetchImpl });
      const results = await r.retrieve('who logged in', 8);
      assert.deepEqual(results, [{ id: 'okta:list_users', server: 'okta', name: 'list_users' }]);
    },
  );
});

test('AgentCoreGatewayRetriever.retrieve() throws when the response carries no recognizable tool list', async () => {
  await withEnv(
    { [AGENTCORE_ENV.GATEWAY_URL]: 'https://gw.example.amazonaws.com', [AGENTCORE_ENV.BEARER_TOKEN]: 'tok' },
    async () => {
      const body = JSON.stringify({ jsonrpc: '2.0', id: '1', result: { content: [{ type: 'text', text: 'not json' }] } });
      const fetchImpl = (async () => new Response(body, { status: 200 })) as unknown as typeof fetch;
      const r = new AgentCoreGatewayRetriever({ fetchImpl });
      await assert.rejects(() => r.retrieve('q', 8), AgentCoreGatewayError);
    },
  );
});

// ─── parseSearchResult / splitAgentCoreToolId (pure helpers) ────────────────

test('parseSearchResult accepts a bare tools array under result.structuredContent.tools', () => {
  const body = { result: { structuredContent: { tools: [{ name: 'a___b' }] } } };
  assert.deepEqual(parseSearchResult(body), [{ name: 'a___b' }]);
});

test('parseSearchResult throws on a non-object body', () => {
  assert.throws(() => parseSearchResult(null), AgentCoreGatewayError);
  assert.throws(() => parseSearchResult('a string'), AgentCoreGatewayError);
});

test('parseSearchResult throws when result is absent', () => {
  assert.throws(() => parseSearchResult({}), AgentCoreGatewayError);
});

test('splitAgentCoreToolId splits target___tool into server:name; passes through an unqualified name', () => {
  assert.deepEqual(splitAgentCoreToolId('stripe-target___create_refund'), {
    server: 'stripe-target',
    name: 'create_refund',
    id: 'stripe-target:create_refund',
  });
  assert.deepEqual(splitAgentCoreToolId('bare_tool_name'), {
    server: 'bare_tool_name',
    name: 'bare_tool_name',
    id: 'bare_tool_name',
  });
});
