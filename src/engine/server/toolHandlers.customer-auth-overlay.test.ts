/**
 * Prove-on-revert for CHARIOT-SPEC §8.6a's dispatch-boundary wiring.
 *
 * §8.6a (CHARIOT-SPEC.md:767, quoted in full in
 * `src/engine/federation/CustomerAuthOverlay.ts`'s module doc comment):
 * "On the first authenticated connect the runtime obtains the live tool
 * list with the customer credential ... " The connect/parity/embed
 * MECHANICS live in `CustomerAuthOverlayConnector`
 * (CustomerAuthOverlay.test.ts covers those in isolation, including a
 * real in-process MCP server for the streamable-HTTP transport). This
 * file covers only the DISPATCH-BOUNDARY WIRING added to
 * `handleCallInner` (toolHandlers.ts, immediately before the "REST
 * adapter execution" branch): a `requiresCustomerAuth: true` adapter
 * dispatched over MCP must run the connector before its tools are
 * trusted as dispatchable, must fail closed (no secret in the envelope)
 * on any non-embedded/non-not-applicable status, and a non-auth adapter
 * must never touch the connector at all.
 *
 * Run (after tsc): node --test dist/engine/server/toolHandlers.customer-auth-overlay.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { handleCall, handleQuery } from './toolHandlers.js';
import type { CallContext, QueryContext } from './toolHandlers.js';
import type { ChariotState, AdapterEntry } from './ChariotState.js';
import type {
  CustomerAuthOverlayConnector,
  OverlayConnectResult,
  OverlayConnectStatus,
} from '../federation/CustomerAuthOverlay.js';
import type { TenantOverlayToolRegistryReader } from '../federation/TenantOverlayToolRegistry.js';
import type { CustomerVerifiedTool } from '../retrieval/overlay/OverlayEmbedder.js';

function makeAdapter(overrides: Partial<AdapterEntry> = {}): AdapterEntry {
  return {
    id: 'overlay-adapter',
    name: 'overlay-adapter',
    type: 'mcp',
    category: 'test',
    requiresCustomerAuth: true,
    mcp: {
      transport: 'streamable-http',
      url: 'https://example.invalid/mcp', // never actually reached when the gate refuses
      toolNames: ['noop'],
    },
    ...overrides,
  } as unknown as AdapterEntry;
}

/** A fake connector recording every `connect()` invocation and returning a
 * scripted status sequence, so the wiring test does not depend on the
 * real vault/live-MCP mechanics (already covered by CustomerAuthOverlay.test.ts). */
function makeFakeConnector(statuses: OverlayConnectStatus[]): {
  connector: CustomerAuthOverlayConnector;
  calls: Array<{ adapterId: string; tenantId: string; userId?: string }>;
} {
  const calls: Array<{ adapterId: string; tenantId: string; userId?: string }> = [];
  let i = 0;
  const connector = {
    async connect(adapter: AdapterEntry, tenantId: string, opts: { userId?: string } = {}): Promise<OverlayConnectResult> {
      calls.push({ adapterId: adapter.id, tenantId, userId: opts.userId });
      const status = statuses[Math.min(i, statuses.length - 1)];
      i++;
      return { status, tenantId, adapterId: adapter.id, reason: status === 'embedded' || status === 'already-embedded' ? undefined : 'scripted-refusal' };
    },
  } as unknown as CustomerAuthOverlayConnector;
  return { connector, calls };
}

function makeState(
  adapter: AdapterEntry,
  connector?: CustomerAuthOverlayConnector,
  registry?: TenantOverlayToolRegistryReader,
): ChariotState {
  return {
    allAdapters: [adapter],
    adapterById: new Map([[adapter.id, adapter]]),
    configuredAdapterIds: new Set([adapter.id]),
    credentials: {},
    fullCatalogFilter: { select: async () => [] },
    toolPreFilter: { select: async () => [] },
    getConfiguredAdapters: () => [adapter],
    loadedAt: new Date(),
    customerAuthOverlayConnector: connector,
    tenantOverlayToolRegistry: registry,
  } as unknown as ChariotState;
}

/** In-memory fake implementing the read surface `toolHandlers.ts` consumes. */
class FakeTenantOverlayToolRegistry implements TenantOverlayToolRegistryReader {
  private readonly store = new Map<string, CustomerVerifiedTool[]>();
  private key(tenantId: string, adapterId: string): string { return `${tenantId}::${adapterId}`; }
  set(tenantId: string, adapterId: string, tools: CustomerVerifiedTool[]): void {
    this.store.set(this.key(tenantId, adapterId), tools);
  }
  getTools(tenantId: string, adapterId: string): readonly CustomerVerifiedTool[] {
    return this.store.get(this.key(tenantId, adapterId)) ?? [];
  }
  hasTool(tenantId: string, adapterId: string, toolName: string): boolean {
    return this.getTools(tenantId, adapterId).some((t) => t.name === toolName);
  }
  getTool(tenantId: string, adapterId: string, toolName: string): CustomerVerifiedTool | undefined {
    return this.getTools(tenantId, adapterId).find((t) => t.name === toolName);
  }
  resolveForTenant(): CustomerVerifiedTool | undefined { return undefined; }
}

/** An adapter shaped exactly like §8.6a's primary case: tool-less at
 * catalog publish (`requiresCustomerAuth: true`, no declared `toolNames`). */
function makeToolLessOverlayAdapter(overrides: Partial<AdapterEntry> = {}): AdapterEntry {
  return {
    id: 'toolless-adapter',
    name: 'toolless-adapter',
    type: 'mcp',
    category: 'test',
    requiresCustomerAuth: true,
    mcp: {
      transport: 'streamable-http',
      url: 'https://example.invalid/mcp',
      // No toolNames — the §8.6a "ships tool-less" case.
    },
    ...overrides,
  } as unknown as AdapterEntry;
}

test('§8.6a R1: requiresCustomerAuth adapter — connect() runs at BOTH gates (handleCallImpl before validation, handleCallInner before dispatch), dispatch proceeds past both on "embedded"', async () => {
  const adapter = makeAdapter();
  const { connector, calls } = makeFakeConnector(['embedded']);
  const state = makeState(adapter, connector);
  const ctx: CallContext = { localMode: true, tenantId: 'tenant-x' };

  const result = await handleCall({ adapter: 'overlay-adapter', tool: 'noop', args: {} }, state, ctx);

  // Team-lead review R1: the connect must run in handleCallImpl BEFORE
  // tool-name validation (or a tool-less adapter's registry can never be
  // populated), AND handleCallInner keeps its own call to the same gate
  // as defense-in-depth immediately before dispatch — so a single
  // successful dispatch now runs the shared gate exactly TWICE.
  assert.equal(calls.length, 2, 'the shared gate runs once in handleCallImpl (pre-validation) and once in handleCallInner (pre-dispatch, defense-in-depth)');
  assert.equal(calls[0]?.adapterId, 'overlay-adapter');
  assert.equal(calls[0]?.tenantId, 'tenant-x');
  assert.equal(calls[1]?.adapterId, 'overlay-adapter');
  assert.equal(calls[1]?.tenantId, 'tenant-x');
  // Dispatch proceeds PAST both gates to the real MCP attempt (which
  // fails against the invalid example.invalid host) — the load-bearing
  // assertion is that the failure is NOT either gate's own refusal code.
  const parsed = JSON.parse(result.content as string) as { code?: string };
  assert.notEqual(parsed.code, 'CUSTOMER_AUTH_OVERLAY_DENIED');
  assert.notEqual(parsed.code, 'CUSTOMER_AUTH_OVERLAY_NOT_WIRED');
});

test('§8.6a: on a second dispatch the gate still calls connect() (relying on the connector\'s OWN one-time-enforcement, not a second cache in toolHandlers) — "already-embedded" still passes the gate', async () => {
  const adapter = makeAdapter();
  // Two handleCall invocations, TWO gate calls each (handleCallImpl +
  // handleCallInner) — 'embedded' the first two times, 'already-embedded'
  // thereafter (makeFakeConnector repeats its last scripted status once
  // the list is exhausted).
  const { connector, calls } = makeFakeConnector(['embedded', 'embedded', 'already-embedded', 'already-embedded']);
  const state = makeState(adapter, connector);
  const ctx: CallContext = { localMode: true, tenantId: 'tenant-x' };

  const r1 = await handleCall({ adapter: 'overlay-adapter', tool: 'noop', args: {} }, state, ctx);
  const r2 = await handleCall({ adapter: 'overlay-adapter', tool: 'noop', args: {} }, state, ctx);

  assert.equal(calls.length, 4, 'the wiring calls connect() twice per dispatch (both gates) — CustomerAuthOverlayConnector.test.ts proves connect() itself is a cheap no-op embed once already-embedded');
  for (const result of [r1, r2]) {
    const parsed = JSON.parse(result.content as string) as { code?: string };
    assert.notEqual(parsed.code, 'CUSTOMER_AUTH_OVERLAY_DENIED');
    assert.notEqual(parsed.code, 'CUSTOMER_AUTH_OVERLAY_NOT_WIRED');
  }
});

for (const status of ['credential-revoked', 'credential-expired', 'no-credential', 'rate-limited', 'connect-failed'] as const) {
  test(`§8.6a: connector status "${status}" fails the dispatch closed with no secret in the envelope`, async () => {
    const adapter = makeAdapter();
    const { connector, calls } = makeFakeConnector([status]);
    const state = makeState(adapter, connector);
    const ctx: CallContext = { localMode: true, tenantId: 'tenant-x' };

    const result = await handleCall({ adapter: 'overlay-adapter', tool: 'noop', args: {} }, state, ctx);

    assert.equal(calls.length, 1);
    assert.equal(result.isError, true, `a "${status}" connector result must fail dispatch closed`);
    assert.equal(result.outcome, 'explicit_failure');
    const raw = result.content as string;
    const parsed = JSON.parse(raw) as { code?: string; error?: string; detail?: string };
    assert.equal(parsed.code, 'CUSTOMER_AUTH_OVERLAY_DENIED');
    assert.equal(parsed.detail, status);
    // Nothing credential-shaped can leak here because OverlayConnectResult
    // never carries credential material (see CustomerAuthOverlay.ts's
    // own contract) — assert the envelope carries only the status literal,
    // never a free-form message from deeper in the stack.
    assert.equal(raw.includes('apiKey'), false);
    assert.equal(raw.includes('apiSecret'), false);
    assert.equal(raw.includes('encrypted'), false);
  });
}

test('§8.6a: no connector wired — a requiresCustomerAuth adapter fails closed rather than dispatching unauthenticated', async () => {
  const adapter = makeAdapter();
  const state = makeState(adapter, undefined);
  const ctx: CallContext = { localMode: true, tenantId: 'tenant-x' };

  const result = await handleCall({ adapter: 'overlay-adapter', tool: 'noop', args: {} }, state, ctx);
  const parsed = JSON.parse(result.content as string) as { code?: string };
  assert.equal(result.isError, true);
  assert.equal(parsed.code, 'CUSTOMER_AUTH_OVERLAY_NOT_WIRED');
});

test('§8.6a: a non-auth (requiresCustomerAuth absent) MCP adapter never touches the connector', async () => {
  const adapter = makeAdapter({ requiresCustomerAuth: false });
  const { connector, calls } = makeFakeConnector(['embedded']);
  const state = makeState(adapter, connector);
  const ctx: CallContext = { localMode: true, tenantId: 'tenant-x' };

  await handleCall({ adapter: 'overlay-adapter', tool: 'noop', args: {} }, state, ctx);

  assert.equal(calls.length, 0, 'a non-auth adapter must never invoke the overlay connector');
});

test('§8.6a: a non-auth adapter with requiresCustomerAuth entirely absent (not just false) never touches the connector', async () => {
  const adapter = makeAdapter();
  delete (adapter as { requiresCustomerAuth?: boolean }).requiresCustomerAuth;
  const { connector, calls } = makeFakeConnector(['embedded']);
  const state = makeState(adapter, connector);
  const ctx: CallContext = { localMode: true, tenantId: 'tenant-x' };

  await handleCall({ adapter: 'overlay-adapter', tool: 'noop', args: {} }, state, ctx);

  assert.equal(calls.length, 0);
});

test('§8.6a: a REST-dispatched tool on a requiresCustomerAuth adapter is untouched by the MCP-only overlay gate', async () => {
  // §8.6a names only the streamable-HTTP/SSE and stdio MCP transports; a
  // REST-surfaced tool takes the existing §10.5 credential path.
  const adapter = makeAdapter({
    requiresCustomerAuth: true,
    mcp: undefined,
    rest: { module: './does-not-exist.js', className: 'DoesNotExist', toolNames: ['noop'] },
  } as unknown as Partial<AdapterEntry>);
  const { connector, calls } = makeFakeConnector(['embedded']);
  const state = makeState(adapter, connector);
  const ctx: CallContext = { localMode: true, tenantId: 'tenant-x' };

  await handleCall({ adapter: 'overlay-adapter', tool: 'noop', args: {} }, state, ctx);

  assert.equal(calls.length, 0, 'a REST dispatch mechanism must never invoke the MCP-only overlay connector');
});

// ─── §8.6a tenant overlay tool registry — dispatchability (team-lead review 2026-09-05) ──

test('§8.6a: a tool-less adapter\'s call is refused before any overlay tool is recorded', async () => {
  const adapter = makeToolLessOverlayAdapter();
  const registry = new FakeTenantOverlayToolRegistry(); // nothing recorded
  const { connector, calls } = makeFakeConnector(['embedded']);
  const state = makeState(adapter, connector, registry);
  const ctx: CallContext = { localMode: true, tenantId: 'tenant-a' };

  const result = await handleCall({ adapter: 'toolless-adapter', tool: 'send_invoice', args: {} }, state, ctx);

  const parsed = JSON.parse(result.content as string) as { code?: string };
  assert.equal(result.isError, true);
  assert.equal(parsed.code, 'TOOL_NOT_REGISTERED');
  // R1: handleCallImpl's gate runs the connect FIRST (unconditionally, for
  // any requiresCustomerAuth MCP adapter) — it succeeds ('embedded'), but
  // the registry it just embedded into is a DIFFERENT fake (`registry`,
  // never populated by this generic `makeFakeConnector`), so validation
  // still refuses. One connect call, then an early return — handleCallInner
  // (and its own second gate call) is never reached.
  assert.equal(calls.length, 1, 'the connect() runs once (handleCallImpl, pre-validation) before validation refuses and returns early');
});

test('§8.6a: the SAME tool is accepted once recorded in the tenant\'s overlay registry', async () => {
  const adapter = makeToolLessOverlayAdapter();
  const registry = new FakeTenantOverlayToolRegistry();
  registry.set('tenant-a', 'toolless-adapter', [{ name: 'send_invoice', description: 'Send an invoice', inputSchema: {} }]);
  const { connector, calls } = makeFakeConnector(['embedded']);
  const state = makeState(adapter, connector, registry);
  const ctx: CallContext = { localMode: true, tenantId: 'tenant-a' };

  const result = await handleCall({ adapter: 'toolless-adapter', tool: 'send_invoice', args: {} }, state, ctx);

  const parsed = JSON.parse(result.content as string) as { code?: string };
  // Dispatch proceeds PAST both the tool-registration check and the
  // overlay connect gate (real MCP dispatch then fails against the fake
  // host — a DIFFERENT, later failure than either gate's own refusal).
  assert.notEqual(parsed.code, 'TOOL_NOT_REGISTERED');
  assert.notEqual(parsed.code, 'CUSTOMER_AUTH_OVERLAY_DENIED');
  assert.notEqual(parsed.code, 'CUSTOMER_AUTH_OVERLAY_NOT_WIRED');
  // R1: the gate now runs TWICE for a successful dispatch — once in
  // handleCallImpl (before validation, which passes because the tool is
  // already in the registry) and once in handleCallInner (defense-in-depth,
  // before the real MCP attempt).
  assert.equal(calls.length, 2, 'the overlay connect gate runs at both handleCallImpl and handleCallInner');
});

test('§8.6a: a second tenant is refused — tenant A\'s recorded overlay tool never dispatches for tenant B', async () => {
  const adapter = makeToolLessOverlayAdapter();
  const registry = new FakeTenantOverlayToolRegistry();
  registry.set('tenant-a', 'toolless-adapter', [{ name: 'send_invoice', description: '', inputSchema: {} }]);
  const { connector, calls } = makeFakeConnector(['embedded']);
  const state = makeState(adapter, connector, registry);
  const ctxB: CallContext = { localMode: true, tenantId: 'tenant-b' };

  const result = await handleCall({ adapter: 'toolless-adapter', tool: 'send_invoice', args: {} }, state, ctxB);

  const parsed = JSON.parse(result.content as string) as { code?: string };
  assert.equal(result.isError, true);
  assert.equal(parsed.code, 'TOOL_NOT_REGISTERED', 'tenant B must see the SAME refusal as if no tool were ever recorded');
  // R1: the connect still runs once (handleCallImpl's gate does not know
  // in advance which tenant's registry validation will refuse) — it is
  // the SUBSEQUENT registry check, scoped to tenant B, that refuses.
  assert.equal(calls.length, 1);
});

test('§8.6a: a corrupt registry at the dispatch-mechanism fallback fails closed with a distinct code, never a false acceptance', async () => {
  const adapter = makeToolLessOverlayAdapter();
  const throwingRegistry: TenantOverlayToolRegistryReader = {
    getTools: () => { throw new Error('disk read failed'); },
    hasTool: () => { throw new Error('disk read failed'); },
    getTool: () => { throw new Error('disk read failed'); },
    resolveForTenant: () => undefined,
  };
  const { connector, calls } = makeFakeConnector(['embedded']);
  const state = makeState(adapter, connector, throwingRegistry);
  const ctx: CallContext = { localMode: true, tenantId: 'tenant-a' };

  const result = await handleCall({ adapter: 'toolless-adapter', tool: 'send_invoice', args: {} }, state, ctx);

  const parsed = JSON.parse(result.content as string) as { code?: string };
  assert.equal(result.isError, true);
  assert.equal(parsed.code, 'CUSTOMER_AUTH_OVERLAY_REGISTRY_CORRUPT');
  // R1: the connect (gate 1, handleCallImpl) runs and succeeds before the
  // registry is ever consulted for validation — the corruption is only
  // discovered at the registry-lookup step AFTER that connect, which then
  // returns immediately, so handleCallInner's gate 2 is never reached.
  assert.equal(calls.length, 1, 'a corrupt registry is discovered only after the pre-validation connect runs; dispatch never proceeds further');
});

// ─── §8.6a chariot_query listing union (team-lead review 2026-09-05) ────────

function makeQueryState(adapter: AdapterEntry, registry?: TenantOverlayToolRegistryReader): ChariotState {
  const tool = { name: 'noop', description: '', inputSchema: {}, parameters: {}, server: adapter.id, tier: 'unofficial' };
  const verdict = { tools: [tool], confidence: 1, abstain: false, degraded: false, legsUsed: [] };
  return {
    allAdapters: [adapter],
    adapterById: new Map([[adapter.id, adapter]]),
    configuredAdapterIds: new Set([adapter.id]),
    credentials: {},
    fullCatalogFilter: { selectWithVerdict: () => verdict, select: async () => [tool] },
    toolPreFilter: { selectWithVerdict: () => verdict, select: async () => [tool] },
    getConfiguredAdapters: () => [adapter],
    loadedAt: new Date(),
    tenantOverlayToolRegistry: registry,
  } as unknown as ChariotState;
}

test('§8.6a: chariot_query lists the tenant\'s overlay tools for a requiresCustomerAuth adapter, unioned with any declared tools', async () => {
  const adapter = makeToolLessOverlayAdapter({ mcp: { transport: 'streamable-http', url: 'https://example.invalid/mcp', toolNames: ['noop'] } } as unknown as Partial<AdapterEntry>);
  const registry = new FakeTenantOverlayToolRegistry();
  registry.set('tenant-a', 'toolless-adapter', [{ name: 'send_invoice', description: 'Send an invoice', inputSchema: { type: 'object' } }]);
  const state = makeQueryState(adapter, registry);
  const ctx: QueryContext = { tenantId: 'tenant-a' };

  const result = (await handleQuery({ query: 'invoice tools' }, state, ctx)) as { matchedAdapters?: Array<{ id: string; tools: Array<{ name: string }> }> };

  const match = result.matchedAdapters?.find((m) => m.id === 'toolless-adapter');
  assert.ok(match, `expected toolless-adapter in matchedAdapters, got: ${JSON.stringify(result)}`);
  const names = match!.tools.map((t) => t.name).sort();
  assert.deepEqual(names, ['noop', 'send_invoice']);
});

test('§8.6a: chariot_query for a DIFFERENT tenant never lists tenant A\'s overlay tools', async () => {
  const adapter = makeToolLessOverlayAdapter({ mcp: { transport: 'streamable-http', url: 'https://example.invalid/mcp', toolNames: ['noop'] } } as unknown as Partial<AdapterEntry>);
  const registry = new FakeTenantOverlayToolRegistry();
  registry.set('tenant-a', 'toolless-adapter', [{ name: 'send_invoice', description: '', inputSchema: {} }]);
  const state = makeQueryState(adapter, registry);
  const ctx: QueryContext = { tenantId: 'tenant-b' };

  const result = (await handleQuery({ query: 'invoice tools' }, state, ctx)) as { matchedAdapters?: Array<{ id: string; tools: Array<{ name: string }> }> };

  const match = result.matchedAdapters?.find((m) => m.id === 'toolless-adapter');
  assert.ok(match, `expected toolless-adapter in matchedAdapters, got: ${JSON.stringify(result)}`);
  assert.deepEqual(match!.tools.map((t) => t.name), ['noop'], 'tenant B must see ONLY the declared tool, never tenant A\'s overlay tool');
});

test('§8.6a: chariot_query listing degrades to declared-tools-only on a corrupt registry, rather than failing the whole query', async () => {
  const adapter = makeToolLessOverlayAdapter({ mcp: { transport: 'streamable-http', url: 'https://example.invalid/mcp', toolNames: ['noop'] } } as unknown as Partial<AdapterEntry>);
  const throwingRegistry: TenantOverlayToolRegistryReader = {
    getTools: () => { throw new Error('disk read failed'); },
    hasTool: () => { throw new Error('disk read failed'); },
    getTool: () => { throw new Error('disk read failed'); },
    resolveForTenant: () => undefined,
  };
  const state = makeQueryState(adapter, throwingRegistry);
  const ctx: QueryContext = { tenantId: 'tenant-a' };

  const result = (await handleQuery({ query: 'invoice tools' }, state, ctx)) as { matchedAdapters?: Array<{ id: string; tools: Array<{ name: string }> }> };

  const match = result.matchedAdapters?.find((m) => m.id === 'toolless-adapter');
  assert.ok(match, `expected toolless-adapter in matchedAdapters despite the corrupt registry, got: ${JSON.stringify(result)}`);
  assert.deepEqual(match!.tools.map((t) => t.name), ['noop']);
});

// ─── §8.6a R1 (team-lead review, BLOCKING): connect must run BEFORE validation ──

/** A connector fake that behaves like the real one on a successful embed:
 * it POPULATES the given registry with the live tool list, exactly as
 * `CustomerAuthOverlayConnector.doConnect` calls `registry.recordTools()`
 * after a successful embed. Lets these tests prove the ordering fix: a
 * tool-less adapter's FIRST call (empty registry) must still succeed when
 * the live list includes it, because the connect ran BEFORE validation. */
function makeEmbeddingFakeConnector(
  registry: FakeTenantOverlayToolRegistry,
  liveToolNames: string[],
): { connector: CustomerAuthOverlayConnector; calls: Array<{ adapterId: string; tenantId: string }> } {
  const calls: Array<{ adapterId: string; tenantId: string }> = [];
  const connector = {
    async connect(adapter: AdapterEntry, tenantId: string): Promise<OverlayConnectResult> {
      calls.push({ adapterId: adapter.id, tenantId });
      registry.set(tenantId, adapter.id, liveToolNames.map((name) => ({ name, description: '', inputSchema: {} })));
      return { status: 'embedded', tenantId, adapterId: adapter.id };
    },
  } as unknown as CustomerAuthOverlayConnector;
  return { connector, calls };
}

test('§8.6a R1: the FIRST call of a tool the live tools/list returns succeeds — empty registry, connect populates it before validation runs', async () => {
  const adapter = makeToolLessOverlayAdapter();
  const registry = new FakeTenantOverlayToolRegistry(); // empty — no prior connect
  const { connector, calls } = makeEmbeddingFakeConnector(registry, ['send_invoice', 'get_balance']);
  const state = makeState(adapter, connector, registry);
  const ctx: CallContext = { localMode: true, tenantId: 'tenant-a' };

  assert.equal(registry.hasTool('tenant-a', 'toolless-adapter', 'send_invoice'), false, 'precondition: registry starts empty');

  const result = await handleCall({ adapter: 'toolless-adapter', tool: 'send_invoice', args: {} }, state, ctx);

  // The pre-validation connect (handleCallImpl) populates the registry, so
  // validation passes and dispatch reaches handleCallInner's own gate too
  // (defense-in-depth, a cheap re-check) — two total connect() calls.
  assert.equal(calls.length, 2, 'the connect runs at both gates once validation passes');
  const parsed = JSON.parse(result.content as string) as { code?: string };
  assert.notEqual(parsed.code, 'TOOL_NOT_REGISTERED', 'the FIRST call must not be refused — the connect that populates the registry has not had a chance to run under the old (broken) ordering');
  assert.notEqual(parsed.code, 'CUSTOMER_AUTH_OVERLAY_DENIED');
  assert.notEqual(parsed.code, 'CUSTOMER_AUTH_OVERLAY_NOT_WIRED');
});

test('§8.6a R1: a tool the live list does NOT return is refused AFTER the connect still runs', async () => {
  const adapter = makeToolLessOverlayAdapter();
  const registry = new FakeTenantOverlayToolRegistry();
  const { connector, calls } = makeEmbeddingFakeConnector(registry, ['send_invoice']); // 'delete_invoice' never returned live
  const state = makeState(adapter, connector, registry);
  const ctx: CallContext = { localMode: true, tenantId: 'tenant-a' };

  const result = await handleCall({ adapter: 'toolless-adapter', tool: 'delete_invoice', args: {} }, state, ctx);

  assert.equal(calls.length, 1, 'the connect still runs (it does not know in advance which tool was requested)');
  const parsed = JSON.parse(result.content as string) as { code?: string };
  assert.equal(result.isError, true);
  assert.equal(parsed.code, 'TOOL_NOT_REGISTERED', 'a tool absent from the now-populated registry is still refused');
});

test('§8.6a R1: a refused connect (revoked credential) returns DENIED before any registry lookup', async () => {
  const adapter = makeToolLessOverlayAdapter();
  const registry = new FakeTenantOverlayToolRegistry();
  let registryQueried = false;
  const spiedRegistry: TenantOverlayToolRegistryReader = {
    getTools: (...args) => { registryQueried = true; return registry.getTools(...args); },
    hasTool: (...args) => { registryQueried = true; return registry.hasTool(...args); },
    getTool: (...args) => { registryQueried = true; return registry.getTool(...args); },
    resolveForTenant: () => undefined,
  };
  const connector = {
    async connect(a: AdapterEntry, tenantId: string): Promise<OverlayConnectResult> {
      return { status: 'credential-revoked', tenantId, adapterId: a.id };
    },
  } as unknown as CustomerAuthOverlayConnector;
  const state = makeState(adapter, connector, spiedRegistry);
  const ctx: CallContext = { localMode: true, tenantId: 'tenant-a' };

  const result = await handleCall({ adapter: 'toolless-adapter', tool: 'send_invoice', args: {} }, state, ctx);

  const parsed = JSON.parse(result.content as string) as { code?: string; detail?: string };
  assert.equal(result.isError, true);
  assert.equal(parsed.code, 'CUSTOMER_AUTH_OVERLAY_DENIED');
  assert.equal(parsed.detail, 'credential-revoked');
  assert.equal(registryQueried, false, 'a refused connect must short-circuit BEFORE the registry is ever consulted');
});
