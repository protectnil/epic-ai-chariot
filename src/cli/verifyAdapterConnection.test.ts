/**
 * @epicai/chariot — tests for src/cli/verifyAdapterConnection.ts
 * CHARIOT::§17.2::13
 */
import { describe, it, mock, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { verifyAdapterConnection } from './verifyAdapterConnection.js';
import type { AdapterEntry } from '../engine/server/ChariotState.js';

function adapter(overrides: Partial<AdapterEntry> = {}): AdapterEntry {
  return { id: 'pubmed', name: 'PubMed', ...overrides } as AdapterEntry;
}

describe('verifyAdapterConnection — CHARIOT::§17.2::13', () => {
  it('reports ok with the discovered tool count on success', async () => {
    const result = await verifyAdapterConnection(
      adapter({ tools: [{ name: 'a', dispatchMechanisms: ['mcp'] }, { name: 'b', dispatchMechanisms: ['mcp'] }] }),
      async () => ({ ok: true, toolCount: 2 }),
    );
    assert.equal(result.ok, true);
    assert.equal(result.toolCount, 2);
    assert.equal(result.adapterId, 'pubmed');
    assert.equal(result.countMismatch, false);
    assert.ok(result.latencyMs >= 0);
  });

  it('reports ok:false with the dispatcher-provided reason on failure', async () => {
    const result = await verifyAdapterConnection(adapter(), async () => ({ ok: false, reason: 'ECONNREFUSED' }));
    assert.equal(result.adapterId, 'pubmed');
    assert.equal(result.ok, false);
    assert.equal((result as { reason?: string }).reason, 'ECONNREFUSED');
  });

  it('reports ok:false when the dispatcher throws, without throwing itself', async () => {
    const result = await verifyAdapterConnection(adapter(), async () => {
      throw new Error('spawn ENOENT');
    });
    assert.equal(result.ok, false);
    assert.equal((result as { reason?: string }).reason, 'spawn ENOENT');
  });

  it('CH-50: flags a mismatch when the live count disagrees with the catalog-declared count', async () => {
    const result = await verifyAdapterConnection(
      adapter({ rest: { toolCount: 25 } } as Partial<AdapterEntry>),
      async () => ({ ok: true, toolCount: 0 }),
    );
    assert.equal(result.ok, true);
    assert.equal(result.toolCount, 0);
    assert.equal(result.declaredToolCount, 25);
    assert.equal(result.countMismatch, true);
  });

  it('does not flag a mismatch when the catalog declares no count at all', async () => {
    const result = await verifyAdapterConnection(adapter(), async () => ({ ok: true, toolCount: 5 }));
    assert.equal(result.declaredToolCount, undefined);
    assert.equal(result.countMismatch, false);
  });

  it('prefers tools[].length, then rest.toolCount, then mcp.toolCount as the declared count', async () => {
    const result = await verifyAdapterConnection(
      adapter({
        tools: [{ name: 'a', dispatchMechanisms: ['mcp'] }],
        rest: { toolCount: 99 } as Partial<AdapterEntry>,
        mcp: { toolCount: 100 } as Partial<AdapterEntry>,
      } as Partial<AdapterEntry>),
      async () => ({ ok: true, toolCount: 1 }),
    );
    assert.equal(result.declaredToolCount, 1);
    assert.equal(result.countMismatch, false);
  });
});

describe('verifyAdapterConnection — timeout enforcement (fake timers)', () => {
  before(() => {
    mock.timers.enable({ apis: ['setTimeout'] });
  });
  after(() => {
    mock.timers.reset();
  });

  it('reports a timeout failure when the dispatcher never resolves within timeoutMs', async () => {
    const hangingDispatcher = () => new Promise<never>(() => {}); // never resolves
    const promise = verifyAdapterConnection(adapter(), hangingDispatcher, 5000);
    mock.timers.tick(5000);
    const result = await promise;
    assert.equal(result.ok, false);
    assert.equal((result as { reason?: string }).reason, 'timeout');
  });

  it('resolves with the dispatcher result when it completes before the timeout', async () => {
    const fastDispatcher = async () => ({ ok: true as const, toolCount: 3 });
    const promise = verifyAdapterConnection(adapter(), fastDispatcher, 5000);
    mock.timers.tick(10);
    const result = await promise;
    assert.equal(result.ok, true);
    assert.equal(result.toolCount, 3);
  });

  it('enforces the timeout independently even if the dispatcher ignores its timeoutMs argument', async () => {
    const ignoresTimeout = () => new Promise<never>(() => {}); // ignores the passed timeoutMs, hangs forever
    const promise = verifyAdapterConnection(adapter(), ignoresTimeout, 1000);
    mock.timers.tick(1000);
    const result = await promise;
    assert.equal(result.ok, false);
    assert.equal((result as { reason?: string }).reason, 'timeout');
  });
});
