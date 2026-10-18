/**
 * AS::§2.5::5 — ADAPTER-STANDARD-MAY-2026.md:460: "**Non-idempotent
 * (declared):** The tool's `inputSchema` MUST carry
 * `x-chariot-idempotent: false`. The dispatcher MUST NOT retry;
 * failures surface as a single attempt."
 *
 * Prior to this test, no dispatch code path anywhere in
 * src/engine/federation/FederationManager.ts or src/engine/mcp-servers/
 * base.ts read a tool's OWN `inputSchema['x-chariot-idempotent']` flag at
 * all — retries were governed exclusively by the per-ADAPTER
 * `DEFAULT_FAILURE_POLICY` / catalog `failurePolicy` (retry x3 on
 * timeout/rate_limit/5xx), regardless of any tool's declared idempotency.
 * The only per-tool idempotency read in FederationManager.callTool used a
 * DIFFERENT, adapter-level vocabulary (`idempotent: 'safe'|'unsafe'|
 * 'unknown'`) solely to attach an `Idempotency-Key` header — it never
 * suppressed retries.
 *
 * This suite proves the dispatcher now (a) makes a single attempt and
 * surfaces the failure with zero retries when the dispatched TOOL's
 * inputSchema carries `x-chariot-idempotent: false`, (b) still retries
 * normally when the flag is `true` or absent (the EARS default), and
 * (c) the per-tool no-retry override applies even when the per-ADAPTER
 * catalog entry's own failurePolicy says 'retry' AND the adapter is
 * simultaneously flagged idempotent-unsafe at the catalog level (proving
 * the two idempotency vocabularies are independent and both take effect
 * together: the Idempotency-Key header is still attached on the single
 * attempt).
 *
 * Deterministic + fast: backoff is configured to 1ms via the
 * fetchWithRetryTelemetry `config` argument so the retrying cases do not
 * sleep for real backoff durations.
 *
 * Run (after tsc): node --test dist/engine/federation/FederationManager.non-idempotent-no-retry.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { FederationManager } from './FederationManager.js';
import { MCPAdapterBase } from '../mcp-servers/base.js';
import type { MCPAdapter } from './adapters/base.js';
import type { AdapterCatalog, AdapterCatalogEntry } from './AdapterCatalog.js';
import type { Tool, ToolResult, ConnectionStatus, FailurePolicy, Idempotent } from '../types/index.js';

/** Tool whose inputSchema (`parameters`) optionally carries the AS §2.5
 *  `x-chariot-idempotent` flag. readOnlyHint:true so the destructive-
 *  annotation approval gate does not short-circuit dispatch. */
function makeTool(server: string, name: string, idempotentFlag?: boolean): Tool {
  const parameters: Record<string, unknown> = { type: 'object', properties: {} };
  if (idempotentFlag !== undefined) parameters['x-chariot-idempotent'] = idempotentFlag;
  return {
    name,
    description: `test tool ${name}`,
    parameters,
    server,
    tier: 'direct',
    annotations: { readOnlyHint: true },
  };
}

/** A real MCPAdapterBase subclass whose callTool() dispatches through the
 *  ACTUAL fetchWithRetryTelemetry retry engine (protected on the base
 *  class) against a stubbed global fetch — this is the only way to prove
 *  the AS §2.5::5 acceptance criterion ("the dispatcher SHALL NOT
 *  retry... surface as a single attempt") against the real retry loop
 *  rather than a bypassed mock. */
class RetryProbeAdapter extends MCPAdapterBase implements MCPAdapter {
  status: ConnectionStatus = 'connected';
  constructor(readonly name: string, private readonly toolsList: Tool[]) { super(); }
  async connect(): Promise<void> {}
  async disconnect(): Promise<void> {}
  async listTools(): Promise<Tool[]> { return this.toolsList; }
  async ping(): Promise<number> { return 1; }
  async callTool(name: string): Promise<ToolResult> {
    const startedAt = Date.now();
    // 1ms backoff so a retrying case in this suite does not sleep for
    // real exponential-backoff durations (default 1s/2s/4s).
    const { response, retryCount, retryReasons } = await (this as unknown as {
      fetchWithRetryTelemetry: (
        url: string,
        options: RequestInit,
        config?: { initialBackoffMs?: number; maxBackoffMs?: number },
      ) => Promise<{ response: Response; retryCount: number; retryReasons: string[] }>;
    }).fetchWithRetryTelemetry(
      `https://retry-probe.installed-vendor.example.com/${name}`,
      { method: 'POST' },
      { initialBackoffMs: 1, maxBackoffMs: 1 },
    );
    return {
      content: await response.text(),
      isError: response.status >= 400,
      server: this.name,
      tool: name,
      durationMs: Date.now() - startedAt,
      retryCount,
      retryReasons,
      outcome: response.status >= 400 ? 'unknown' : 'success',
    };
  }
}

/** Stub global.fetch: always returns a retryable 503, always records the
 *  attempt count and the Idempotency-Key header seen on each attempt. */
function stubAlways503(): { calls: Array<{ headers: Record<string, string> }>; restore: () => void } {
  const originalFetch = globalThis.fetch;
  const calls: Array<{ headers: Record<string, string> }> = [];
  globalThis.fetch = (async (_url: unknown, init?: RequestInit) => {
    const headers: Record<string, string> = {};
    if (init?.headers) {
      for (const [k, v] of Object.entries(init.headers as Record<string, string>)) headers[k] = v;
    }
    calls.push({ headers });
    return new Response(JSON.stringify({ error: '503 from stub' }), {
      status: 503,
      statusText: 'Service Unavailable',
      headers: { 'Content-Type': 'application/json' },
    });
  }) as typeof fetch;
  return { calls, restore: () => { globalThis.fetch = originalFetch; } };
}

const SRV = 'retry-probe-srv';

function makeFakeCatalog(entry: AdapterCatalogEntry | undefined): AdapterCatalog {
  // Minimal structural double of AdapterCatalog exposing exactly the
  // three members FederationManager.callTool actually consults
  // (byName / isRevoked / getRevocationDetails). Constructing a real
  // AdapterCatalog requires a signed on-disk bundle, which is
  // orthogonal to what this suite is proving.
  return {
    byName: (name: string) => (name === SRV ? entry : undefined),
    isRevoked: () => false,
    getRevocationDetails: () => undefined,
  } as unknown as AdapterCatalog;
}

async function wire(
  idempotentFlag: boolean | undefined,
  catalogEntry?: AdapterCatalogEntry,
): Promise<{ manager: FederationManager }> {
  const adapter = new RetryProbeAdapter(SRV, [makeTool(SRV, 'probe', idempotentFlag)]);
  const manager = new FederationManager(
    { servers: [{ name: SRV, transport: 'streamable-http', url: 'https://retry-probe.installed-vendor.example.com/mcp' }] },
    catalogEntry ? { catalog: makeFakeCatalog(catalogEntry) } : {},
  );
  await manager.connect(
    SRV,
    { name: SRV, transport: 'streamable-http', url: 'https://retry-probe.installed-vendor.example.com/mcp' },
    adapter,
  );
  return { manager };
}

test('AS::§2.5::5 — x-chariot-idempotent:false makes exactly ONE attempt, no retry', async () => {
  const stub = stubAlways503();
  try {
    const { manager } = await wire(false);
    const result = await manager.callTool(`${SRV}:probe`, {});
    assert.equal(stub.calls.length, 1, 'the dispatcher must reach the upstream exactly once — no retry');
    assert.equal(result.retryCount, 0, 'retryCount must be 0 — the failure surfaces as a single attempt');
    assert.equal(result.isError, true, 'the failure itself is still surfaced (not silently swallowed)');
  } finally {
    stub.restore();
  }
});

test('AS::§2.5::5 — x-chariot-idempotent:true retries normally (not force-stopped)', async () => {
  const stub = stubAlways503();
  try {
    const { manager } = await wire(true);
    const result = await manager.callTool(`${SRV}:probe`, {});
    assert.ok(stub.calls.length > 1, `explicit true must still retry per the default policy, got ${stub.calls.length} attempt(s)`);
    assert.ok((result.retryCount ?? 0) > 0, 'retryCount must be > 0 for an explicitly idempotent tool');
  } finally {
    stub.restore();
  }
});

test('AS::§2.5::5 — absent x-chariot-idempotent retries normally (EARS default: idempotent unless declared)', async () => {
  const stub = stubAlways503();
  try {
    const { manager } = await wire(undefined);
    const result = await manager.callTool(`${SRV}:probe`, {});
    assert.ok(stub.calls.length > 1, `absent flag must default to idempotent (retries), got ${stub.calls.length} attempt(s)`);
    assert.ok((result.retryCount ?? 0) > 0, 'retryCount must be > 0 when the flag is absent');
  } finally {
    stub.restore();
  }
});

test('AS::§2.5::5 — the per-TOOL no-retry override beats a per-ADAPTER catalog failurePolicy that says retry, AND coexists with the per-ADAPTER Idempotency-Key mechanism', async () => {
  const stub = stubAlways503();
  try {
    // Adapter-level catalog entry deliberately configured to RETRY (a
    // generous budget) and to mark the ADAPTER idempotent-unsafe, which
    // independently drives the Idempotency-Key header per
    // FederationManager.callTool's `needsKey = idempotent !== 'safe'`.
    const retryEverythingPolicy: FailurePolicy = { onTimeout: 'retry', onRateLimit: 'retry', on5xx: 'retry', maxRetries: 5 };
    const adapterLevelIdempotent: Idempotent = 'unsafe';
    const catalogEntry = {
      name: SRV,
      displayName: SRV,
      version: '1.0.0',
      category: 'test',
      keywords: [],
      toolNames: ['probe'],
      description: 'retry-probe fixture',
      author: 'protectnil',
      failurePolicy: retryEverythingPolicy,
      idempotent: adapterLevelIdempotent,
    } as unknown as AdapterCatalogEntry;

    const { manager } = await wire(false, catalogEntry);
    const result = await manager.callTool(`${SRV}:probe`, {});

    assert.equal(
      stub.calls.length,
      1,
      'the per-tool x-chariot-idempotent:false override must force a single attempt even though the adapter-level failurePolicy says retry',
    );
    assert.equal(result.retryCount, 0, 'retryCount must be 0 despite the adapter-level retry-everything policy');
    assert.ok(
      typeof stub.calls[0]?.headers['Idempotency-Key'] === 'string' && stub.calls[0].headers['Idempotency-Key'].length > 0,
      'the Idempotency-Key header (driven by the SEPARATE per-adapter idempotent:"unsafe" field) must still be attached on the single attempt',
    );
  } finally {
    stub.restore();
  }
});
