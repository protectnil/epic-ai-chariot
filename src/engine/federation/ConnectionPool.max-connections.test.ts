/**
 * Regression eval: ConnectionPool enforces a maxConnections ceiling (§7.3::1).
 *
 * The defect this exists to catch: ConnectionPool had no size ceiling of any
 * kind — `grep -n 'maxConnections' ConnectionPool.ts` returned zero matches
 * pre-fix. connect() would accept unboundedly many adapters. This test
 * constructs a pool with maxConnections=1, connects one adapter
 * successfully, then asserts a second connect() is REJECTED for being over
 * capacity. It would FAIL against the pre-fix code (the second connect()
 * would succeed silently).
 *
 * Run (after tsc):
 *   node --test dist/engine/federation/ConnectionPool.max-connections.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { ConnectionPool } from './ConnectionPool.js';
import type { MCPAdapter } from './adapters/base.js';
import type { ConnectionStatus, ServerConnection, Tool, ToolResult } from '../types/index.js';

function makeStubAdapter(name: string): MCPAdapter {
  return {
    name,
    status: 'connected' as ConnectionStatus,
    async connect() {},
    async disconnect() {},
    async listTools(): Promise<Tool[]> { return []; },
    async callTool(): Promise<ToolResult> {
      return { content: [], isError: false, server: name, tool: '', durationMs: 0 };
    },
    async ping() { return 0; },
  };
}

function makeConfig(name: string): ServerConnection {
  return { name, transport: 'stdio', command: 'true' } as unknown as ServerConnection;
}

test('connect() refuses a new adapter once maxConnections is reached', async () => {
  const pool = new ConnectionPool(undefined, undefined, undefined, 1);

  await pool.connect(makeConfig('alpha'), makeStubAdapter('alpha'));
  assert.equal(pool.size, 1);

  await assert.rejects(
    () => pool.connect(makeConfig('beta'), makeStubAdapter('beta')),
    /capacity/i,
  );
  assert.equal(pool.size, 1);

  await pool.disconnectAll();
});
