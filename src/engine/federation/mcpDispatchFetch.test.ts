/**
 * @epicai/chariot — regression: MCP dispatch fetch suppresses the
 * SDK's standalone GET SSE listening stream while delegating every POST.
 *
 * Deterministic + offline: exercises createMcpDispatchFetch against a stub
 * base fetch, asserting (a) a GET (the standalone SSE stream the SDK opens
 * after notifications/initialized) is answered with a synthetic 405 WITHOUT
 * touching the network, so the SDK treats it as "no SSE stream" and continues;
 * and (b) POSTs (initialize / tools/list / tools/call) are delegated verbatim.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createMcpDispatchFetch } from './mcpDispatchFetch.js';

test('standalone GET SSE stream is answered with 405, never dialed out', async () => {
  const calls: Array<{ url: string; method: string }> = [];
  const base = (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = input instanceof Request ? input.url : String(input);
    const method = (init?.method ?? (input instanceof Request ? input.method : 'GET')).toUpperCase();
    calls.push({ url, method });
    return Promise.resolve(new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } }));
  };
  const f = createMcpDispatchFetch(base);

  // The standalone SSE GET the SDK opens after `notifications/initialized`.
  const getResp = await f('https://mcp.example.com/x/mcp', { method: 'GET', headers: { accept: 'text/event-stream' } });
  assert.equal(getResp.status, 405, 'GET must return synthetic 405 so the SDK skips the standalone stream');
  assert.equal(calls.length, 0, 'GET must NOT reach the network — no starving long-lived stream');

  // A default-method (no method) request is a GET per the fetch spec → suppressed.
  const bareResp = await f('https://mcp.example.com/x/mcp');
  assert.equal(bareResp.status, 405);
  assert.equal(calls.length, 0);
});

test('POSTs (JSON-RPC sends) are delegated to the base fetch verbatim', async () => {
  const calls: Array<{ url: string; method: string; body: unknown }> = [];
  const base = (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    calls.push({ url: String(input), method: (init?.method ?? 'GET').toUpperCase(), body: init?.body });
    return Promise.resolve(new Response('{"jsonrpc":"2.0","id":1,"result":{}}', { status: 200, headers: { 'content-type': 'application/json' } }));
  };
  const f = createMcpDispatchFetch(base);

  const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} });
  const resp = await f('https://mcp.example.com/x/mcp', { method: 'POST', body, headers: { 'content-type': 'application/json' } });
  assert.equal(resp.status, 200);
  assert.equal(calls.length, 1, 'POST must be delegated to the base fetch');
  assert.equal(calls[0].method, 'POST');
  assert.equal(calls[0].body, body, 'POST body must pass through unmodified');
});
