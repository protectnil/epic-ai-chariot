/**
 * Prove-on-revert for CH-31 (CHARIOT §23.2 typed-outcome / no-silent-false-
 * success) applied to the stdio transport: a malformed frame that the SDK
 * would silently drop leaves an id-bearing client hanging with no typed
 * outcome — so bindStdio must answer every malformed frame.
 *
 * stdio.ts:62-99 (bindStdio/handleLine): the SDK's StdioServerTransport
 * silently drops a parse/validation failure (routes it to `onerror`, writes
 * nothing) which would hang an id-bearing client forever. bindStdio line-
 * buffers stdin itself and answers:
 *   - unparseable JSON                       -> -32700 Parse error, id:null
 *   - parseable but invalid JSON-RPC 2.0     -> -32600 Invalid Request,
 *     (wrong version / missing method /         id echoed when recoverable
 *      batch array / invalid id)
 *   - well-formed frame                      -> forwarded, NOT answered
 *                                                with an error on stdout
 *
 * Failure enumeration this locks in: (a) garbage text, (b) wrong jsonrpc
 * version, (c) missing method, (d) batch array, (e) empty/whitespace line
 * (must produce NO output at all), (f) well-formed request (must NOT be
 * answered with a -32700/-32600 error).
 *
 * Run (after tsc): node --test dist/engine/server/transports/stdio.malformed-frame.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import { bindStdio } from './stdio.js';

interface JsonRpcErrorFrame {
  jsonrpc: '2.0';
  id: string | number | null;
  error: { code: number; message: string };
}

function makeStubServer(): McpServer {
  // bindStdio only calls server.connect(transport); it never dispatches
  // through our stub for this test (we only exercise the line-buffering /
  // validation layer that runs BEFORE the SDK transport sees anything).
  return { connect: async () => undefined } as unknown as McpServer;
}

/** Collect newline-delimited JSON frames written to a captured stdout stream. */
function makeCapturingStdout(): { stream: PassThrough; lines: () => string[] } {
  const stream = new PassThrough();
  const chunks: string[] = [];
  stream.on('data', (chunk: Buffer) => chunks.push(chunk.toString('utf8')));
  return {
    stream,
    lines: () => chunks.join('').split('\n').filter((l) => l.trim() !== ''),
  };
}

async function drive(inputLines: string[]): Promise<string[]> {
  const stdin = new PassThrough();
  const { stream: stdout, lines } = makeCapturingStdout();
  await bindStdio(makeStubServer(), stdin, stdout);
  for (const line of inputLines) {
    stdin.write(`${line}\n`);
  }
  stdin.end();
  // Let the 'end' handler (which flushes any trailing partial line) run.
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
  return lines();
}

test('stdio-frame (a): unparseable JSON -> -32700 Parse error, id:null', async () => {
  const lines = await drive(['not json']);
  assert.equal(lines.length, 1, `expected exactly one response line, got: ${JSON.stringify(lines)}`);
  const frame = JSON.parse(lines[0]) as JsonRpcErrorFrame;
  assert.equal(frame.jsonrpc, '2.0');
  assert.equal(frame.id, null);
  assert.equal(frame.error.code, -32700);
  assert.equal(frame.error.message, 'Parse error');
});

test('stdio-frame (b): wrong jsonrpc version -> -32600 Invalid Request, id echoed', async () => {
  const lines = await drive(['{"jsonrpc":"1.0","id":1,"method":"ping"}']);
  assert.equal(lines.length, 1, `expected exactly one response line, got: ${JSON.stringify(lines)}`);
  const frame = JSON.parse(lines[0]) as JsonRpcErrorFrame;
  assert.equal(frame.error.code, -32600);
  assert.equal(frame.error.message, 'Invalid Request');
  assert.equal(frame.id, 1);
});

test('stdio-frame (c): missing method -> -32600 Invalid Request, id echoed', async () => {
  const lines = await drive(['{"jsonrpc":"2.0","id":2}']);
  assert.equal(lines.length, 1, `expected exactly one response line, got: ${JSON.stringify(lines)}`);
  const frame = JSON.parse(lines[0]) as JsonRpcErrorFrame;
  assert.equal(frame.error.code, -32600);
  assert.equal(frame.id, 2);
});

test('stdio-frame (d): batch array -> -32600 Invalid Request', async () => {
  const lines = await drive(['[{"jsonrpc":"2.0","id":3,"method":"ping"}]']);
  assert.equal(lines.length, 1, `expected exactly one response line, got: ${JSON.stringify(lines)}`);
  const frame = JSON.parse(lines[0]) as JsonRpcErrorFrame;
  assert.equal(frame.error.code, -32600);
  // A JSON array has no recoverable `.id` -> must be null, not "3".
  assert.equal(frame.id, null);
});

test('stdio-frame (e): empty/whitespace line produces no output', async () => {
  const lines = await drive(['   ', '']);
  assert.equal(lines.length, 0, `expected no output for blank lines, got: ${JSON.stringify(lines)}`);
});

test('stdio-frame (f): well-formed request is FORWARDED to the SDK (observably) and NOT answered with a protocol error', async () => {
  // A recording server captures what the SDK transport actually receives off
  // the internal `forward` stream. Asserting only stdout.length===0 (as the
  // prior version did) is ALSO satisfied by a reverted impl that silently DROPS
  // valid frames — so we additionally assert the frame was delivered.
  const received: unknown[] = [];
  const stdin = new PassThrough();
  const { stream: stdout, lines } = makeCapturingStdout();
  const server = {
    connect: async (transport: { onmessage?: (m: unknown) => void; start: () => Promise<void> }) => {
      transport.onmessage = (m: unknown) => received.push(m);
      await transport.start();
    },
  } as unknown as McpServer;
  await bindStdio(server, stdin, stdout);
  stdin.write('{"jsonrpc":"2.0","id":4,"method":"ping","params":{}}\n');
  stdin.end();
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
  // Not answered with a local -32700/-32600 protocol error on stdout ...
  assert.equal(lines().length, 0, `well-formed frame must not be answered on stdout, got: ${JSON.stringify(lines())}`);
  // ... AND actually delivered to the SDK transport (proves forwarding, not a silent drop).
  assert.equal(received.length, 1, `well-formed frame must be forwarded to the SDK, got: ${JSON.stringify(received)}`);
  assert.equal((received[0] as { method?: string }).method, 'ping');
  assert.equal((received[0] as { id?: number }).id, 4);
});
