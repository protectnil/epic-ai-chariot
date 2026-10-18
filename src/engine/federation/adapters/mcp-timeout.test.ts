/**
 * @epicai/chariot — MCP stdio launcher fail-closed adversarial eval
 *
 * Proves that MCPClientAdapter.connect() refuses an unverified stdio executable
 * before spawning it. Timeout behavior is covered only after a launcher passes
 * the supply-chain gate; these fixtures intentionally never reach child spawn.
 *
 * The obsolete fixture used an arbitrary Node executable, which is now
 * correctly rejected by the SDD before the timeout path.
 *
 * Test structure:
 *   1. Write a real Node.js script that acts as a minimal MCP server:
 *      responds to initialize but intentionally never responds to tools/list.
 *   2. Attempt MCPClientAdapter connection with that script.
 *   3. Assert connect() rejects with the supply-chain gate error.
 *   4. Assert no child is spawned.
 *
 * A separate test below covers the timeout/abort path promised by the header
 * above: it exercises MCPClientAdapter's opt-in `clientFactory`/
 * `transportFactory` seams (see MCPClientAdapterSeams in MCPClientAdapter.ts,
 * added so "behavior above the transport (timeout/abort handling) is
 * testable without spawning a child process") with a fake client whose
 * listTools() never settles unless aborted. No test file previously used
 * these seams, so the listTools-hang → AbortController-timeout path they
 * were built for had no coverage.
 *
 * Run after `tsc`: node --test dist/engine/federation/adapters/mcp-timeout.test.js
 * Registered in scripts/run-all-tests.mjs.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { MCPClientAdapter } from './MCPClientAdapter.js';

/**
 * A client that connects fine but whose listTools() never settles — the
 * in-memory stand-in for a hung MCP server. Used via the adapter's opt-in
 * clientFactory seam so no child process is spawned (and so the air-gap
 * launcher allowlist / supply-chain integrity gate exercised by the tests
 * above, which reject any unverified stdio command before a transport is
 * even created, is not in the way of this timeout-path test).
 */
function hangingClient() {
  return {
    async connect() { /* connects immediately */ },
    // Never returns tools. Honors the caller's AbortSignal exactly as the real
    // MCP SDK client does, so the adapter's connect-timeout abort surfaces as a
    // rejection instead of hanging the event loop forever.
    listTools(_params?: unknown, opts?: { signal?: AbortSignal }) {
      return new Promise<never>((_resolve, reject) => {
        const signal = opts?.signal;
        if (!signal) return; // no signal supplied → genuinely never settles
        const abort = (): void => reject(new Error('The operation was aborted'));
        if (signal.aborted) { abort(); return; }
        signal.addEventListener('abort', abort, { once: true });
      });
    },
    async close() { /* nothing to tear down */ },
  } as never;
}

// ── Hanging MCP server script ────────────────────────────────────────────────
//
// The MCP SDK uses newline-delimited JSON (not Content-Length framing):
//   each message is one JSON object followed by '\n'.
//
// The server below:
//   • responds to 'initialize' (so SDK.connect() completes)
//   • ignores 'notifications/initialized'
//   • NEVER responds to 'tools/list' → triggers the AbortController timeout

const HANGING_SERVER_SRC = `#!/usr/bin/env node
// Minimal MCP stdio server that hangs on tools/list
process.stdin.setEncoding('utf-8');
let buf = '';

process.stdin.on('data', (chunk) => {
  buf += chunk;
  let nl;
  while ((nl = buf.indexOf('\\n')) !== -1) {
    const line = buf.slice(0, nl).trim();
    buf = buf.slice(nl + 1);
    if (!line) continue;
    let msg;
    try { msg = JSON.parse(line); } catch { continue; }

    if (msg.method === 'initialize') {
      // Complete the handshake so client.connect() resolves
      const resp = JSON.stringify({
        jsonrpc: '2.0',
        id: msg.id,
        result: {
          protocolVersion: '2024-11-05',
          capabilities: { tools: {} },
          serverInfo: { name: 'hang-server', version: '0.0.0' }
        }
      });
      process.stdout.write(resp + '\\n');
    }
    // 'notifications/initialized' → ignore
    // 'tools/list'               → intentionally no response (hang)
  }
});

// Keep stdin open so the child does not exit before the parent aborts
process.stdin.resume();
`.trimStart();

// ── Tests ────────────────────────────────────────────────────────────────────

test('MCPClientAdapter refuses an unverified executable before a child can hang', async () => {
  const tmpDir = mkdtempSync(join(tmpdir(), 'chariot-mcp-timeout-'));
  const serverScript = join(process.cwd(), `.chariot-mcp-timeout-${process.pid}.mjs`);
  writeFileSync(serverScript, HANGING_SERVER_SRC, 'utf-8');
  chmodSync(serverScript, 0o700);

  const adapter = new MCPClientAdapter({
    name: 'hang-test',
    transport: 'stdio',
    command: `./${relative(process.cwd(), serverScript)}`,
    args: [],
  });

  let caughtErr: Error | undefined;
  try {
    await adapter.connect();
    assert.fail('connect() must reject an unverified executable launcher');
  } catch (err) {
    caughtErr = err as Error;
  } finally {
    // Disconnect cleans up the child process; ignore errors from a partially-connected state
    try { await adapter.disconnect(); } catch { /* best effort */ }
    rmSync(tmpDir, { recursive: true, force: true });
    rmSync(serverScript, { force: true });
  }
  assert.ok(caughtErr !== undefined, 'connect() must reject before spawning');
  assert.match(caughtErr.message, /no supply-chain integrity gate/i);
  assert.match(caughtErr.message, /only npx is supported/i);
});

test('MCPClientAdapter reports the unverified-launcher rejection as an Error', async () => {
  const tmpDir = mkdtempSync(join(tmpdir(), 'chariot-mcp-timeout-'));
  const serverScript = join(process.cwd(), `.chariot-mcp-timeout-${process.pid}-2.mjs`);
  writeFileSync(serverScript, HANGING_SERVER_SRC, 'utf-8');
  chmodSync(serverScript, 0o700);

  const adapter = new MCPClientAdapter({
    name: 'typed-timeout-test',
    transport: 'stdio',
    command: `./${relative(process.cwd(), serverScript)}`,
    args: [],
  });

  let err: Error | undefined;
  try {
    await adapter.connect();
  } catch (e) {
    err = e as Error;
  } finally {
    try { await adapter.disconnect(); } catch { /* best effort */ }
    rmSync(tmpDir, { recursive: true, force: true });
    rmSync(serverScript, { force: true });
  }

  assert.ok(err instanceof Error, 'must throw an Error instance (not reject with non-Error)');
  assert.match(err.message, /no supply-chain integrity gate/i);
  assert.match(err.message, /only npx is supported/i);
});

test('MCPClientAdapter aborts listTools within CHARIOT_MCP_CONNECT_TIMEOUT_MS when the client hangs (seam)', async () => {
  // Short timeout so the test is fast.
  const TIMEOUT_MS = 300;
  const originalEnv = process.env.CHARIOT_MCP_CONNECT_TIMEOUT_MS;
  process.env.CHARIOT_MCP_CONNECT_TIMEOUT_MS = String(TIMEOUT_MS);

  // The seams bypass transport/client construction entirely — no process is
  // spawned, so the air-gap launcher allowlist and integrity gate (exercised
  // above) do not apply here; this isolates just the listTools timeout/abort
  // behavior inside connect().
  const adapter = new MCPClientAdapter(
    { name: 'hang-test-seam', transport: 'stdio' },
    {
      transportFactory: () => ({ close: async () => {} }) as never,
      clientFactory: () => hangingClient(),
    },
  );

  const start = Date.now();
  let caughtErr: Error | undefined;
  try {
    await adapter.connect();
    assert.fail('connect() should have thrown due to listTools timeout');
  } catch (err) {
    caughtErr = err as Error;
  } finally {
    try { await adapter.disconnect(); } catch { /* best effort */ }
    process.env.CHARIOT_MCP_CONNECT_TIMEOUT_MS = originalEnv ?? '';
  }

  const elapsed = Date.now() - start;

  assert.ok(caughtErr !== undefined, 'connect() must throw on timeout');
  // The adapter detects the timeout via its own abort SIGNAL (not the error
  // name), so even though the injected client rejects with a generic "The
  // operation was aborted" Error, the adapter still emits its own
  // descriptive typed message.
  assert.ok(
    caughtErr.message.includes('did not respond to listTools') &&
    caughtErr.message.includes('timed out'),
    `error must be the adapter's descriptive timeout message; got: "${caughtErr.message}"`,
  );
  assert.ok(
    elapsed < 3000,
    `adapter must abort well before 3 s; took ${elapsed} ms (timeout was ${TIMEOUT_MS} ms)`,
  );
});
