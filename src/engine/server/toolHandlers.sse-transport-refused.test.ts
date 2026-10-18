/**
 * Prove-on-revert for CHARIOT::§7.2::3 — SSE SHALL NOT be
 * implemented at the federation layer; a `transport:'sse'` dispatch SHALL
 * error out (no network activity) and SHALL NOT be advertised as a
 * supported transport.
 *
 * CHARIOT-SPEC.md §7.2 (verbatim, docs/spec/CHARIOT-SPEC.md:598-601 —
 * repo-local mirror docs/product/CHARIOT-SPEC.md:59-61): "SSE is not
 * implemented at the federation layer despite
 * src/engine/server/toolHandlers.ts:546-568 accepting a `transport: 'sse'`
 * parameter. The accepting code path errors out on dispatch; SSE
 * transport must not be advertised to customers as supported until the
 * federation adapter implements it."
 *
 * Before the original fix, the `transport:'sse'` branch in handleCallImpl
 * (toolHandlers.ts, "MCP SSE adapter") dynamically imported
 * `SSEClientTransport` from `@modelcontextprotocol/sdk/client/sse.js` and
 * opened a real network connection via `client.connect(transport)`. It also
 * counted as dispatchable in `isDispatchable()` (ChariotState.ts), so an
 * sse-transport catalog entry was surfaced to customers as a selectable
 * adapter that would fail (or hang, per the SSEClientTransport connect()
 * dead-end noted in the removed code) instead of never showing up at all.
 *
 * Follow-on gate finding: the original fix refused ONLY the exact lowercase
 * value `adapter.mcp?.transport === 'sse'`. A catalog/tool-surface value
 * such as `'SSE'`, `'Sse'`, `'server-sent-events'`, `'eventsource'`, or any
 * other value that is not one of the two implemented transports (`stdio`,
 * `streamable-http`) fell through to whatever MCPClientAdapter/the SDK did
 * with an unrecognized transport instead of the distinct fail-closed
 * refusal. The dispatch-time check (toolHandlers.ts, "MCP
 * unsupported-transport refusal") and the catalog-load check
 * (`isDispatchable()`, ChariotState.ts) are now both an ALLOW-LIST of
 * exactly `stdio` and `streamable-http` — nothing is normalized/lowercased
 * first, so no alias or case-variant can accidentally match an
 * `=== 'sse'`-only check and slip through. The tests below cover the
 * alias/case-variant classes: `SSE`, `server-sent-events`, `eventsource`,
 * and a catalog-shaped record.
 *
 * Run (after tsc): node --test dist/engine/server/toolHandlers.sse-transport-refused.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { handleCall } from './toolHandlers.js';
import type { CallContext } from './toolHandlers.js';
import type { ChariotState } from './ChariotState.js';
import { isDispatchable } from './ChariotState.js';
import type { AdapterEntry } from './ChariotState.js';
import type { ChariotRegistryEntry } from '../../catalog/artifacts.js';

/** Any MCP transport value other than the two implemented ones — used to
 * drive the alias/case-variant/undefined failure enumeration below. */
function makeStateWithTransportAdapter(adapterId: string, transport: string | undefined): ChariotState {
  const adapter = {
    id: adapterId,
    name: adapterId,
    type: 'mcp',
    category: 'test',
    mcp: {
      ...(transport !== undefined ? { transport } : {}),
      url: 'https://example.invalid/sse',
      tools: [{ name: 'noop', inputSchema: { type: 'object', properties: {} } }],
    },
  } as unknown as AdapterEntry;
  return {
    allAdapters: [adapter],
    adapterById: new Map([[adapterId, adapter]]),
    configuredAdapterIds: new Set([adapterId]),
    credentials: {},
    fullCatalogFilter: { select: async () => [] },
    toolPreFilter: { select: async () => [] },
    getConfiguredAdapters: () => [adapter],
    loadedAt: new Date(),
  } as unknown as ChariotState;
}

function makeStateWithSseAdapter(adapterId: string): ChariotState {
  return makeStateWithTransportAdapter(adapterId, 'sse');
}

test('§7.2::3: a transport:sse dispatch errors with errorClass transport_not_supported, before any network activity', async () => {
  // Spy on every network primitive the removed SSE path could reach for —
  // fetch (used by createMcpDispatchFetch / the SDK's HTTP layer) and the
  // global EventSource constructor (the SSE wire protocol itself). Neither
  // may be invoked by a refused dispatch.
  let fetchCalled = false;
  let eventSourceConstructed = false;
  const originalFetch = globalThis.fetch;
  const originalEventSource = (globalThis as unknown as { EventSource?: unknown }).EventSource;
  (globalThis as unknown as { fetch: typeof fetch }).fetch = (async (...args: Parameters<typeof fetch>) => {
    fetchCalled = true;
    return originalFetch(...args);
  }) as typeof fetch;
  class SpyEventSource {
    constructor() {
      eventSourceConstructed = true;
    }
  }
  (globalThis as unknown as { EventSource: unknown }).EventSource = SpyEventSource;

  try {
    const state = makeStateWithSseAdapter('sse-adapter');
    // localMode:true opts into the single-user/stdio-trust RBAC bypass
    // (resolveRbacDecision, toolHandlers.ts) so this call exercises the
    // transport refusal itself rather than the earlier, transport-agnostic
    // anonymous-call gate — see the toolHandlers.resolver-fanout-bucket.test.ts
    // convention for the same opt-in.
    const ctx: CallContext = { localMode: true };
    const result = await handleCall({ adapter: 'sse-adapter', tool: 'noop', args: {} }, state, ctx);
    const parsed = JSON.parse(result.content as string) as { error?: string };

    assert.equal(result.isError, true, 'an sse-transport dispatch must be an error');
    assert.equal(parsed.error, 'transport_not_supported', `wrong error code, got ${result.content}`);
    assert.equal(result.errorClass, 'transport_not_supported', `wrong errorClass, got ${JSON.stringify(result)}`);
    assert.equal(result.outcome, 'explicit_failure', `wrong outcome, got ${JSON.stringify(result)}`);
    assert.equal(fetchCalled, false, 'refusing an sse dispatch must not touch the network via fetch');
    assert.equal(eventSourceConstructed, false, 'refusing an sse dispatch must not open an EventSource/SSE stream');
  } finally {
    (globalThis as unknown as { fetch: typeof fetch }).fetch = originalFetch;
    if (originalEventSource === undefined) {
      delete (globalThis as unknown as { EventSource?: unknown }).EventSource;
    } else {
      (globalThis as unknown as { EventSource: unknown }).EventSource = originalEventSource;
    }
  }
});

test('§7.2::3: a transport:sse dispatch errors even when the per-tool schema gate would otherwise reject the call — the transport refusal fires first', async () => {
  // The pre-fix code ran validateForHandlerInner (the invalid_arguments
  // gate) BEFORE the SSE connect attempt; the fixed code must refuse the
  // transport itself and never reach the schema gate, so a call with
  // arguments that would fail schema validation still surfaces
  // transport_not_supported, not invalid_arguments.
  const state = makeStateWithSseAdapter('sse-adapter-2');
  const ctx: CallContext = { localMode: true };
  const result = await handleCall(
    { adapter: 'sse-adapter-2', tool: 'noop', args: { unexpectedField: 'x'.repeat(10) } },
    state,
    ctx,
  );
  const parsed = JSON.parse(result.content as string) as { error?: string };
  assert.equal(parsed.error, 'transport_not_supported', `transport refusal must precede schema validation, got ${result.content}`);
  assert.equal(result.errorClass, 'transport_not_supported');
});

test('§7.2::3: isDispatchable() never marks an sse-transport adapter dispatchable — SSE is not advertised to customers', () => {
  const sseAdapter = {
    id: 'sse-adapter-3',
    name: 'sse-adapter-3',
    type: 'mcp',
    category: 'test',
    mcp: { transport: 'sse', url: 'https://example.invalid/sse' },
  } as unknown as AdapterEntry;
  assert.equal(
    isDispatchable(sseAdapter),
    false,
    'an sse-transport adapter must be dropped at catalog-load time, never surfaced in the routing index or chariot_list',
  );
});

test('§7.2::3: the streamable-http and stdio dispatchable checks are unaffected by the sse removal', () => {
  const httpAdapter = {
    id: 'http-adapter',
    name: 'http-adapter',
    type: 'mcp',
    category: 'test',
    mcp: { transport: 'streamable-http', url: 'https://example.invalid/mcp' },
  } as unknown as AdapterEntry;
  const stdioAdapter = {
    id: 'stdio-adapter',
    name: 'stdio-adapter',
    type: 'mcp',
    category: 'test',
    mcp: { transport: 'stdio', command: 'echo' },
  } as unknown as AdapterEntry;
  assert.equal(isDispatchable(httpAdapter), true, 'streamable-http adapters must remain dispatchable');
  assert.equal(isDispatchable(stdioAdapter), true, 'stdio adapters must remain dispatchable');
});

test('§7.2::3 guard: SSEClientTransport / text/event-stream must not appear in toolHandlers.js dispatch code, only in the historical citation comment', () => {
  const src = readFileSync(fileURLToPath(new URL('./toolHandlers.js', import.meta.url)), 'utf8');
  assert.ok(
    !/SSEClientTransport/.test(src),
    'toolHandlers.js must not import or construct SSEClientTransport anywhere — the federation layer never dispatches over SSE',
  );
});

// ── Follow-on: alias / case-variant / undefined transport classes ─────────
// The gate finding this closes: the ORIGINAL fix refused only the exact
// string 'sse'. Each class below is a value a real catalog/tool-surface
// record could carry that a caller might expect to alias to SSE, or that
// simply is not one of the two implemented transports — every one of them
// MUST refuse with the SAME distinct errorClass as the literal 'sse' case,
// not fall through to a generic/undifferentiated error.

const UNSUPPORTED_TRANSPORT_CLASSES: ReadonlyArray<{ readonly label: string; readonly transport: string | undefined }> = [
  { label: 'SSE (uppercase)', transport: 'SSE' },
  { label: 'Sse (mixed case)', transport: 'Sse' },
  { label: 'server-sent-events (alias)', transport: 'server-sent-events' },
  { label: 'eventsource (alias)', transport: 'eventsource' },
  { label: 'empty string', transport: '' },
  { label: 'undefined (mcp mechanism resolved, no transport field)', transport: undefined },
];

for (const { label, transport } of UNSUPPORTED_TRANSPORT_CLASSES) {
  test(`§7.2::3 follow-on: transport ${JSON.stringify(label)} dispatch refuses with errorClass transport_not_supported, before any network activity`, async () => {
    let fetchCalled = false;
    let eventSourceConstructed = false;
    const originalFetch = globalThis.fetch;
    const originalEventSource = (globalThis as unknown as { EventSource?: unknown }).EventSource;
    (globalThis as unknown as { fetch: typeof fetch }).fetch = (async (...args: Parameters<typeof fetch>) => {
      fetchCalled = true;
      return originalFetch(...args);
    }) as typeof fetch;
    class SpyEventSource {
      constructor() {
        eventSourceConstructed = true;
      }
    }
    (globalThis as unknown as { EventSource: unknown }).EventSource = SpyEventSource;

    try {
      const adapterId = `unsupported-transport-${label.replace(/[^a-z0-9]+/gi, '-')}`;
      const state = makeStateWithTransportAdapter(adapterId, transport);
      const ctx: CallContext = { localMode: true };
      const result = await handleCall({ adapter: adapterId, tool: 'noop', args: {} }, state, ctx);
      const parsed = JSON.parse(result.content as string) as { error?: string };

      assert.equal(result.isError, true, `a transport ${JSON.stringify(transport)} dispatch must be an error`);
      assert.equal(parsed.error, 'transport_not_supported', `wrong error code for transport ${JSON.stringify(transport)}, got ${result.content}`);
      assert.equal(result.errorClass, 'transport_not_supported', `wrong errorClass for transport ${JSON.stringify(transport)}, got ${JSON.stringify(result)}`);
      assert.equal(result.outcome, 'explicit_failure', `wrong outcome for transport ${JSON.stringify(transport)}, got ${JSON.stringify(result)}`);
      assert.equal(fetchCalled, false, `refusing transport ${JSON.stringify(transport)} must not touch the network via fetch`);
      assert.equal(eventSourceConstructed, false, `refusing transport ${JSON.stringify(transport)} must not open an EventSource/SSE stream`);
    } finally {
      (globalThis as unknown as { fetch: typeof fetch }).fetch = originalFetch;
      if (originalEventSource === undefined) {
        delete (globalThis as unknown as { EventSource?: unknown }).EventSource;
      } else {
        (globalThis as unknown as { EventSource: unknown }).EventSource = originalEventSource;
      }
    }
  });

  test(`§7.2::3 follow-on: isDispatchable() never marks transport ${JSON.stringify(label)} dispatchable`, () => {
    const adapter = {
      id: `unsupported-transport-dispatchable-${label.replace(/[^a-z0-9]+/gi, '-')}`,
      name: 'x',
      type: 'mcp',
      category: 'test',
      mcp: {
        ...(transport !== undefined ? { transport } : {}),
        url: 'https://example.invalid/sse',
        command: 'echo', // present on both fields so neither the stdio nor the streamable-http allow-list branch is skipped for a config reason unrelated to the transport value itself
      },
    } as unknown as AdapterEntry;
    assert.equal(
      isDispatchable(adapter),
      false,
      `an adapter with transport ${JSON.stringify(transport)} must never be dispatchable, even with a url and a command present`,
    );
  });
}

test('§7.2::3 follow-on: a catalog-shaped ChariotRegistryEntry record with transport "sse" is neither dispatchable nor advertised, and refuses at dispatch with the distinct class', async () => {
  // Shaped exactly like a parsed bundle record (src/catalog/artifacts.ts),
  // not a hand-built AdapterEntry — proves the refusal holds for the actual
  // record shape the catalog loader emits, not just a test fixture.
  const catalogRecord: ChariotRegistryEntry = {
    id: 'catalog-sse-adapter',
    name: 'catalog-sse-adapter',
    description: 'test',
    category: 'test',
    keywords: [],
    type: 'mcp',
    mcp: {
      transport: 'sse',
      url: 'https://example.invalid/sse',
      tools: [{ name: 'noop', inputSchema: { type: 'object', properties: {} } }],
    },
  };
  const adapter = catalogRecord as unknown as AdapterEntry;

  assert.equal(
    isDispatchable(adapter),
    false,
    'a catalog record with transport "sse" must never be marked dispatchable — it must not reach the routing index, chariot_list, or a configured set',
  );

  const state: ChariotState = {
    allAdapters: [adapter],
    adapterById: new Map([[catalogRecord.id, adapter]]),
    configuredAdapterIds: new Set([catalogRecord.id]),
    credentials: {},
    fullCatalogFilter: { select: async () => [] },
    toolPreFilter: { select: async () => [] },
    getConfiguredAdapters: () => [adapter],
    loadedAt: new Date(),
  } as unknown as ChariotState;
  const ctx: CallContext = { localMode: true };
  const result = await handleCall({ adapter: catalogRecord.id, tool: 'noop', args: {} }, state, ctx);
  const parsed = JSON.parse(result.content as string) as { error?: string };
  assert.equal(parsed.error, 'transport_not_supported', `a catalog-shaped sse record reaching dispatch anyway must refuse distinctly, got ${result.content}`);
  assert.equal(result.errorClass, 'transport_not_supported');
  assert.equal(result.outcome, 'explicit_failure');
});

// ── W7d follow-on: a GENUINE supported transport (stdio, streamable-http)
// with a malformed/incomplete record must refuse with the distinct
// `adapter_config_invalid` errorClass, never `transport_not_supported` and
// never fall through to the generic unclassified "No executable transport"
// fallback. §7.2's bytes distinguish "is the transport implemented" from
// "is the record for that transport complete" — CHARIOT-SPEC.md §7.2
// (docs/spec/CHARIOT-SPEC.md:598, repo-local mirror
// docs/product/CHARIOT-SPEC.md:59-61): "The two transports currently
// implemented in `MCPClientAdapter` (`src/engine/federation/adapters/
// MCPClientAdapter.ts`) are `stdio` and `streamable-http`." A `stdio`
// record missing `command` (and with no docker pin) or a `streamable-http`
// record missing `url` is a transport the clause names as implemented —
// its incompleteness is a different failure than "not implemented". ────────

function makeStateWithMcpAdapter(
  adapterId: string,
  mcp: Record<string, unknown>,
  adapterFields: Record<string, unknown> = {},
): ChariotState {
  const adapter = {
    id: adapterId,
    name: adapterId,
    type: 'mcp',
    category: 'test',
    ...adapterFields, // top-level adapter fields (e.g. timeoutMs — read as adapter.timeoutMs, NOT adapter.mcp.timeoutMs)
    mcp: {
      ...mcp,
      tools: [{ name: 'noop', inputSchema: { type: 'object', properties: {} } }],
    },
  } as unknown as AdapterEntry;
  return {
    allAdapters: [adapter],
    adapterById: new Map([[adapterId, adapter]]),
    configuredAdapterIds: new Set([adapterId]),
    credentials: {},
    fullCatalogFilter: { select: async () => [] },
    toolPreFilter: { select: async () => [] },
    getConfiguredAdapters: () => [adapter],
    loadedAt: new Date(),
  } as unknown as ChariotState;
}

test('§7.2::3 follow-on: transport "stdio" with no command and no docker pin refuses with errorClass adapter_config_invalid, not transport_not_supported, before any network/spawn activity', async () => {
  let fetchCalled = false;
  const originalFetch = globalThis.fetch;
  (globalThis as unknown as { fetch: typeof fetch }).fetch = (async (...args: Parameters<typeof fetch>) => {
    fetchCalled = true;
    return originalFetch(...args);
  }) as typeof fetch;

  try {
    const state = makeStateWithMcpAdapter('stdio-no-command', { transport: 'stdio' });
    const ctx: CallContext = { localMode: true };
    const result = await handleCall({ adapter: 'stdio-no-command', tool: 'noop', args: {} }, state, ctx);
    const parsed = JSON.parse(result.content as string) as { error?: string };

    assert.equal(result.isError, true, 'a stdio dispatch with no command must be an error');
    assert.equal(parsed.error, 'adapter_config_invalid', `wrong error code, got ${result.content}`);
    assert.equal(result.errorClass, 'adapter_config_invalid', `wrong errorClass, got ${JSON.stringify(result)}`);
    assert.notEqual(result.errorClass, 'transport_not_supported', 'a genuinely-implemented transport with a malformed record must not be classified as transport_not_supported');
    assert.equal(result.outcome, 'explicit_failure', `wrong outcome, got ${JSON.stringify(result)}`);
    assert.equal(fetchCalled, false, 'refusing an incomplete stdio record must not touch the network');
  } finally {
    (globalThis as unknown as { fetch: typeof fetch }).fetch = originalFetch;
  }
});

test('§7.2::3 follow-on: transport "streamable-http" with no url/serverUrl refuses with errorClass adapter_config_invalid, not transport_not_supported, before any network activity', async () => {
  let fetchCalled = false;
  const originalFetch = globalThis.fetch;
  (globalThis as unknown as { fetch: typeof fetch }).fetch = (async (...args: Parameters<typeof fetch>) => {
    fetchCalled = true;
    return originalFetch(...args);
  }) as typeof fetch;

  try {
    const state = makeStateWithMcpAdapter('http-no-url', { transport: 'streamable-http' });
    const ctx: CallContext = { localMode: true };
    const result = await handleCall({ adapter: 'http-no-url', tool: 'noop', args: {} }, state, ctx);
    const parsed = JSON.parse(result.content as string) as { error?: string };

    assert.equal(result.isError, true, 'a streamable-http dispatch with no url must be an error');
    assert.equal(parsed.error, 'adapter_config_invalid', `wrong error code, got ${result.content}`);
    assert.equal(result.errorClass, 'adapter_config_invalid', `wrong errorClass, got ${JSON.stringify(result)}`);
    assert.notEqual(result.errorClass, 'transport_not_supported', 'a genuinely-implemented transport with a malformed record must not be classified as transport_not_supported');
    assert.equal(result.outcome, 'explicit_failure', `wrong outcome, got ${JSON.stringify(result)}`);
    assert.equal(fetchCalled, false, 'refusing an incomplete streamable-http record must not touch the network');
  } finally {
    (globalThis as unknown as { fetch: typeof fetch }).fetch = originalFetch;
  }
});

test('§7.2::3 follow-on: transport "stdio" with a command present is NOT caught by either the transport_not_supported or adapter_config_invalid refusal (it proceeds to real stdio dispatch)', async () => {
  // Uses a nonexistent binary so the real stdio dispatch path fails for an
  // UNRELATED reason (spawn/connect failure) — proving this record cleared
  // BOTH new-and-old refusal gates rather than merely asserting isDispatchable().
  const state = makeStateWithMcpAdapter(
    'stdio-with-command',
    { transport: 'stdio', command: '/nonexistent/definitely-not-a-real-binary-w7d' },
    { timeoutMs: 500 }, // bound worst-case test runtime regardless of environment
  );
  const ctx: CallContext = { localMode: true };
  const result = await handleCall({ adapter: 'stdio-with-command', tool: 'noop', args: {} }, state, ctx);
  assert.notEqual(result.errorClass, 'transport_not_supported', 'a well-formed stdio record must not be refused as transport_not_supported');
  assert.notEqual(result.errorClass, 'adapter_config_invalid', 'a well-formed stdio record must not be refused as adapter_config_invalid');
});

test('§7.2::3 follow-on: transport "streamable-http" with a url present is NOT caught by either the transport_not_supported or adapter_config_invalid refusal (it proceeds to real streamable-http dispatch)', async () => {
  // Uses an .invalid TLD (RFC 2606) so the real dispatch fails for an
  // UNRELATED reason (DNS/connect failure), proving this record cleared
  // both new-and-old refusal gates.
  const state = makeStateWithMcpAdapter(
    'http-with-url',
    { transport: 'streamable-http', url: 'https://w7d-followon.invalid/mcp' },
    { timeoutMs: 500 }, // bound worst-case test runtime regardless of environment
  );
  const ctx: CallContext = { localMode: true };
  const result = await handleCall({ adapter: 'http-with-url', tool: 'noop', args: {} }, state, ctx);
  assert.notEqual(result.errorClass, 'transport_not_supported', 'a well-formed streamable-http record must not be refused as transport_not_supported');
  assert.notEqual(result.errorClass, 'adapter_config_invalid', 'a well-formed streamable-http record must not be refused as adapter_config_invalid');
});

test('§7.2::3 follow-on: isDispatchable() is unchanged by this fix — both malformed shapes remain non-dispatchable', () => {
  const stdioNoCommand = {
    id: 'x1', name: 'x1', type: 'mcp', category: 'test',
    mcp: { transport: 'stdio' },
  } as unknown as AdapterEntry;
  const httpNoUrl = {
    id: 'x2', name: 'x2', type: 'mcp', category: 'test',
    mcp: { transport: 'streamable-http' },
  } as unknown as AdapterEntry;
  assert.equal(isDispatchable(stdioNoCommand), false, 'stdio with no command and no docker pin must remain non-dispatchable');
  assert.equal(isDispatchable(httpNoUrl), false, 'streamable-http with no url must remain non-dispatchable');
});

test('§7.2::3 follow-on: sse and its aliases still refuse with transport_not_supported (unaffected by the adapter_config_invalid split)', async () => {
  for (const transport of ['sse', 'SSE', 'server-sent-events', 'eventsource']) {
    const adapterId = `still-unsupported-${transport.replace(/[^a-z0-9]+/gi, '-')}`;
    const state = makeStateWithMcpAdapter(adapterId, { transport, url: 'https://example.invalid/sse' });
    const ctx: CallContext = { localMode: true };
    const result = await handleCall({ adapter: adapterId, tool: 'noop', args: {} }, state, ctx);
    const parsed = JSON.parse(result.content as string) as { error?: string };
    assert.equal(parsed.error, 'transport_not_supported', `transport ${JSON.stringify(transport)} must still refuse as transport_not_supported, got ${result.content}`);
    assert.equal(result.errorClass, 'transport_not_supported');
  }
});
