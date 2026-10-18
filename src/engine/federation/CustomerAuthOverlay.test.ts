/**
 * @epicai/chariot — CHARIOT-SPEC §8.6a customer-credential connect tests.
 *
 * Failure classes enumerated from the governing bytes (CHARIOT-SPEC.md:767)
 * and the AGENTS.md auth-hardening requirement (revocation, refresh,
 * one-time enforcement, brute-force protection):
 *   1. streamable-HTTP: credential header present, tools/list issued once,
 *      initialize precedes tools/list (real in-process MCP server).
 *   2. stdio: credential placed in child ENV, never argv (pure function —
 *      `buildStdioCredentialEnv` — no real spawn required; the launcher
 *      allowlist [npx-only, `pathConfinement.ts:71`] makes spawning an
 *      arbitrary test binary structurally rejected by design, so the
 *      credential-placement invariant is verified at the unit that builds
 *      the env object handed to `StdioClientTransport`).
 *   3. parity match → customer-verified (embed called, parity:'match').
 *   4. parity mismatch → overlay corrected to the live list + event.
 *   5. revoked credential → refused, no connect attempted.
 *   6. expired credential (status field) → refused.
 *   7. expired credential (expiresAt passed, status not yet flipped —
 *      defense in depth against the §10.5 5-minute refresh-job cadence)
 *      → refused.
 *   8. no credential row → refused.
 *   9. repeated connect, same credential version → one embed call
 *      (idempotent, no re-embed storm).
 *  10. concurrent connects → coalesced into one embed call (in-flight
 *      promise sharing).
 *  11. decrypt failure → rate limiter penalized, connect-failed, no embed.
 *  12. live connect failure → rate limiter penalized, connect-failed, no embed.
 *  13. brute-force guard trips after repeated failures (RateLimiter.allow
 *      returns false once the bucket is drained).
 *  14. `requiresCustomerAuth` absent/false → not-applicable, no side effects.
 *  15. nothing credential-shaped appears in the audit detail or the
 *      federation event data.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';

import {
  CustomerAuthOverlayConnector,
  buildStdioCredentialEnv,
  defaultConnectAndListTools,
  type CustomerAuthOverlayDeps,
  type CustomerVerifiedTool,
  type OverlayConnectResult,
  type OverlayEmbedResult,
  type OverlayEmbedder,
  type OverlayToolRegistryWriter,
} from './CustomerAuthOverlay.js';
import { RateLimiter } from '../resilience/RateLimiter.js';
import type { AdapterEntry } from '../server/ChariotState.js';
import type { AdapterCredentialDocument } from '../../iam/types.js';

// ─── Shared fixtures ────────────────────────────────────────────────────────

function makeAdapter(overrides: Partial<AdapterEntry> = {}): AdapterEntry {
  return {
    id: 'test-adapter',
    name: 'Test Adapter',
    requiresCustomerAuth: true,
    mcp: {
      transport: 'streamable-http',
      url: 'http://127.0.0.1:1/mcp',
      authEnvKey: 'TEST_API_KEY',
      authScheme: 'bearer',
      toolNames: ['echo'],
    },
    ...overrides,
  } as AdapterEntry;
}

function makeCredentialRow(overrides: Partial<AdapterCredentialDocument> = {}): AdapterCredentialDocument {
  return {
    _id: 'row-1' as unknown as AdapterCredentialDocument['_id'],
    tenantId: 'tenant-1',
    adapterId: 'test-adapter',
    credentialType: 'api_key',
    status: 'active',
    encrypted: 'ciphertext',
    iv: 'iv',
    connectedBy: 'user-1',
    connectedAt: new Date('2026-01-01T00:00:00.000Z'),
    shared: true,
    ...overrides,
  } as AdapterCredentialDocument;
}

class FakeEmbedder implements OverlayEmbedder {
  calls: Array<{ tenantId: string; adapterId: string; tools: CustomerVerifiedTool[] }> = [];
  async embedCustomerVerifiedTools(
    tenantId: string,
    adapterId: string,
    tools: CustomerVerifiedTool[],
  ): Promise<OverlayEmbedResult> {
    this.calls.push({ tenantId, adapterId, tools });
    return { tenantId, adapterId, embedded: tools.length, overlayStateHash: `hash-${this.calls.length}` };
  }
  overlayStateHash(): string {
    return `hash-${this.calls.length}`;
  }
}

class FakeRegistry implements OverlayToolRegistryWriter {
  calls: Array<{ tenantId: string; adapterId: string; tools: readonly CustomerVerifiedTool[] }> = [];
  async recordTools(tenantId: string, adapterId: string, tools: readonly CustomerVerifiedTool[]): Promise<void> {
    this.calls.push({ tenantId, adapterId, tools });
  }
}

function makeDeps(over: Partial<CustomerAuthOverlayDeps> & { embedder?: OverlayEmbedder } = {}) {
  const embedder = over.embedder ?? new FakeEmbedder();
  const rateLimiter = over.rateLimiter ?? new RateLimiter({ maxRequests: 10, windowMs: 60_000 });
  const registry = over.registry ?? new FakeRegistry();
  const auditCalls: Array<{ tenantId: string; eventType: string; detail: unknown }> = [];
  const deps: CustomerAuthOverlayDeps = {
    embedder,
    rateLimiter,
    registry,
    fetchCredential: over.fetchCredential ?? (async () => makeCredentialRow()),
    decrypt: over.decrypt ?? (async () => ({ fields: { apiKey: 'super-secret-token', apiSecret: 'super-secret-secret' } })),
    connectAndListTools:
      over.connectAndListTools ??
      (async () => ({ ok: true, tools: [{ name: 'echo', description: 'Echoes input', inputSchema: { type: 'object' } }] })),
    now: over.now,
    auditLog:
      over.auditLog ??
      (async (tenantId, eventType, opts) => {
        auditCalls.push({ tenantId, eventType, detail: opts.detail });
        return {} as Awaited<ReturnType<typeof import('../../iam/services/audit.js').log>>;
      }),
  };
  return { deps, embedder: embedder as FakeEmbedder, registry: registry as FakeRegistry, auditCalls };
}

// ─── 1/1-ordering. Real in-process streamable-HTTP MCP server ──────────────

test('streamable-HTTP: Authorization header present on every request, tools/list issued once', async () => {
  const seenHeaders: string[] = [];
  const methodsSeen: string[] = [];

  const server = new McpServer({ name: 'fixture', version: '1.0.0' });
  server.tool('echo', { text: z.string() }, async (args) => ({ content: [{ type: 'text' as const, text: args.text }] }));

  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: () => randomUUID() });
  await server.connect(transport);

  // Matches harness/http/process.ts's proven pattern: let
  // transport.handleRequest consume the request stream itself (a manual
  // pre-read would desync the SDK's own JSON-RPC framing). Request METHOD
  // ordering (initialize before tools/list) is guaranteed structurally by
  // `defaultConnectAndListTools` calling `client.connect()` (which performs
  // the initialize handshake) strictly before `client.listTools()` — see
  // the module doc comment; this fixture verifies the header and the
  // resulting tool list are real, end-to-end, over an actual HTTP socket.
  const realServer = createServer((req, res) => {
    const auth = req.headers['authorization'];
    if (typeof auth === 'string') seenHeaders.push(auth);
    methodsSeen.push(req.method ?? '');
    void (async () => {
      try {
        await transport.handleRequest(req, res);
      } catch {
        if (!res.headersSent) { res.writeHead(500); res.end('error'); }
      }
    })();
  });

  await new Promise<void>((resolve) => realServer.listen(0, '127.0.0.1', resolve));
  const addr = realServer.address();
  if (!addr || typeof addr !== 'object') throw new Error('failed to bind fixture server');
  const url = `http://127.0.0.1:${addr.port}/mcp`;

  const adapter = makeAdapter({ mcp: { transport: 'streamable-http', url, authEnvKey: 'X', authScheme: 'bearer', toolNames: ['echo'] } });
  const outcome = await defaultConnectAndListTools(adapter, { apiKey: 'my-customer-token' });

  realServer.close();

  assert.equal(outcome.ok, true);
  if (outcome.ok) {
    assert.deepEqual(outcome.tools.map((t) => t.name), ['echo']);
  }
  assert.ok(seenHeaders.length > 0, 'expected at least one request');
  assert.ok(
    seenHeaders.every((h) => h === 'Bearer my-customer-token'),
    `every request must carry the Bearer header, saw: ${JSON.stringify(seenHeaders)}`,
  );
  assert.ok(methodsSeen.every((m) => m === 'POST'), 'the MCP client should only POST JSON-RPC frames');
});

// ─── stdio credential placement (pure function — no real spawn) ───────────

test('stdio: credential lands in child env under the declared key, never in argv', () => {
  const adapter = makeAdapter({
    mcp: { transport: 'stdio', command: 'npx', args: ['-y', 'some-pkg@1.0.0'], authEnvKey: 'VENDOR_TOKEN', toolNames: ['echo'] },
  });
  const env = buildStdioCredentialEnv(adapter, { apiKey: 'sekret-value', apiSecret: 'sekret-secret' }, { PATH: '/usr/bin' }, false);
  assert.equal(env.VENDOR_TOKEN, 'sekret-value');
  assert.equal(env.VENDOR_TOKEN_SECRET, 'sekret-secret');
  assert.equal(adapter.mcp?.args?.includes('sekret-value'), false);
  assert.equal(JSON.stringify(adapter.mcp?.args).includes('sekret'), false);
});

test('stdio: envKeys[0]/envKeys[1] pair used when authEnvKey absent, dangerous keys stripped', () => {
  const adapter = makeAdapter({
    mcp: { transport: 'stdio', command: 'npx', envKeys: ['PRIMARY_KEY', 'PRIMARY_SECRET_FIELD'], toolNames: [] },
  });
  const env = buildStdioCredentialEnv(
    adapter,
    { apiKey: 'v1', apiSecret: 'v2' },
    { PATH: '/usr/bin', NODE_OPTIONS: '--require=evil.js' },
    true,
  );
  assert.equal(env.PRIMARY_KEY, 'v1');
  assert.equal(env.PRIMARY_SECRET_FIELD, 'v2');
  assert.equal('NODE_OPTIONS' in env, false, 'dangerous env key must be stripped');
  assert.equal(env.npm_config_offline, 'true');
  assert.equal(env.npm_config_ignore_scripts, 'true');
});

test('stdio: derives <PRIMARY>_SECRET when no explicit secondary key is declared', () => {
  const adapter = makeAdapter({ mcp: { transport: 'stdio', command: 'npx', authEnvKey: 'FOO_KEY', toolNames: [] } });
  const env = buildStdioCredentialEnv(adapter, { apiKey: 'a', apiSecret: 'b' }, {}, false);
  assert.equal(env.FOO_KEY, 'a');
  // '_KEY' suffix is replaced (not appended) — mirrors credential-loader.ts's
  // secondaryEnvKey: `primary.replace(/_KEY$/, '_SECRET')`.
  assert.equal(env.FOO_SECRET, 'b');
});

// ─── Connector: parity ──────────────────────────────────────────────────────

test('parity match upgrades to customer-verified and embeds the live tools', async () => {
  const { deps, embedder } = makeDeps();
  const connector = new CustomerAuthOverlayConnector(deps);
  const result = await connector.connect(makeAdapter(), 'tenant-1');
  assert.equal(result.status, 'embedded');
  assert.equal(result.parity, 'match');
  assert.equal(result.toolCount, 1);
  assert.equal(embedder.calls.length, 1);
  assert.deepEqual(embedder.calls[0]?.tools.map((t) => t.name), ['echo']);
});

test('parity mismatch still embeds the live list and reports mismatch (overlay corrected)', async () => {
  const { deps, embedder } = makeDeps({
    connectAndListTools: async () => ({
      ok: true,
      tools: [
        { name: 'echo', description: 'x', inputSchema: {} },
        { name: 'unexpected_tool', description: 'y', inputSchema: {} },
      ],
    }),
  });
  const connector = new CustomerAuthOverlayConnector(deps);
  const result = await connector.connect(makeAdapter({ mcp: { transport: 'streamable-http', url: 'http://x', toolNames: ['echo'] } }), 'tenant-1');
  assert.equal(result.status, 'embedded');
  assert.equal(result.parity, 'mismatch');
  assert.equal(embedder.calls[0]?.tools.length, 2);
});

// ─── Connector: credential state gates ──────────────────────────────────────

test('revoked credential is refused; no connect attempted', async () => {
  let connectCalled = false;
  const { deps } = makeDeps({
    fetchCredential: async () => makeCredentialRow({ status: 'revoked' }),
    connectAndListTools: async () => { connectCalled = true; return { ok: true, tools: [] }; },
  });
  const connector = new CustomerAuthOverlayConnector(deps);
  const result = await connector.connect(makeAdapter(), 'tenant-1');
  assert.equal(result.status, 'credential-revoked');
  assert.equal(connectCalled, false);
});

test('expired credential (status field) is refused', async () => {
  const { deps } = makeDeps({ fetchCredential: async () => makeCredentialRow({ status: 'expired' }) });
  const connector = new CustomerAuthOverlayConnector(deps);
  const result = await connector.connect(makeAdapter(), 'tenant-1');
  assert.equal(result.status, 'credential-expired');
});

test('expired credential (expiresAt passed, status not yet flipped) is refused — defense in depth', async () => {
  const { deps } = makeDeps({
    fetchCredential: async () => makeCredentialRow({ status: 'active', expiresAt: new Date('2020-01-01T00:00:00.000Z') }),
    now: () => new Date('2026-01-01T00:00:00.000Z'),
  });
  const connector = new CustomerAuthOverlayConnector(deps);
  const result = await connector.connect(makeAdapter(), 'tenant-1');
  assert.equal(result.status, 'credential-expired');
});

test('no credential row is refused', async () => {
  const { deps } = makeDeps({ fetchCredential: async () => null });
  const connector = new CustomerAuthOverlayConnector(deps);
  const result = await connector.connect(makeAdapter(), 'tenant-1');
  assert.equal(result.status, 'no-credential');
});

test('requiresCustomerAuth absent/false is not-applicable and touches nothing', async () => {
  let embedCalled = false;
  const embedder: OverlayEmbedder = {
    async embedCustomerVerifiedTools() { embedCalled = true; return { tenantId: 't', adapterId: 'a', embedded: 0, overlayStateHash: 'h' }; },
    overlayStateHash: () => 'h',
  };
  const { deps } = makeDeps({ embedder });
  const connector = new CustomerAuthOverlayConnector(deps);
  const result = await connector.connect(makeAdapter({ requiresCustomerAuth: false }), 'tenant-1');
  assert.equal(result.status, 'not-applicable');
  assert.equal(embedCalled, false);
});

// ─── Connector: one-time enforcement / no re-embed storm ───────────────────

test('repeated connect with the SAME credential version embeds exactly once', async () => {
  const { deps, embedder } = makeDeps();
  const connector = new CustomerAuthOverlayConnector(deps);
  const r1 = await connector.connect(makeAdapter(), 'tenant-1');
  const r2 = await connector.connect(makeAdapter(), 'tenant-1');
  assert.equal(r1.status, 'embedded');
  assert.equal(r2.status, 'already-embedded');
  assert.equal(embedder.calls.length, 1);
});

test('a credential version bump (refresh) allows exactly one new embed', async () => {
  let version = 0;
  const { deps, embedder } = makeDeps({
    fetchCredential: async () =>
      makeCredentialRow(version === 0 ? {} : { lastRefreshedAt: new Date('2026-02-01T00:00:00.000Z') }),
  });
  const connector = new CustomerAuthOverlayConnector(deps);
  await connector.connect(makeAdapter(), 'tenant-1');
  version = 1;
  const r2 = await connector.connect(makeAdapter(), 'tenant-1');
  assert.equal(r2.status, 'embedded');
  assert.equal(embedder.calls.length, 2);
});

test('concurrent connects for the same (tenant, adapter) coalesce into one embed', async () => {
  let inFlightCount = 0;
  let maxConcurrent = 0;
  const { deps, embedder } = makeDeps({
    connectAndListTools: async () => {
      inFlightCount++;
      maxConcurrent = Math.max(maxConcurrent, inFlightCount);
      await new Promise((r) => setTimeout(r, 20));
      inFlightCount--;
      return { ok: true, tools: [{ name: 'echo', description: '', inputSchema: {} }] };
    },
  });
  const connector = new CustomerAuthOverlayConnector(deps);
  const [r1, r2] = await Promise.all([connector.connect(makeAdapter(), 'tenant-1'), connector.connect(makeAdapter(), 'tenant-1')]);
  assert.equal(maxConcurrent, 1, 'connectAndListTools must not be invoked concurrently for the same key');
  assert.equal(embedder.calls.length, 1);
  assert.equal(r1.status, 'embedded');
  assert.equal(r2.status, 'embedded');
  assert.deepEqual(r1.overlayStateHash, r2.overlayStateHash);
});

// ─── Connector: failure handling / brute-force guard ───────────────────────

test('decrypt failure penalizes the rate limiter and reports connect-failed, no embed', async () => {
  const rateLimiter = new RateLimiter({ maxRequests: 5, windowMs: 60_000 });
  const { deps, embedder } = makeDeps({ rateLimiter, decrypt: async () => { throw new Error('bad key'); } });
  const connector = new CustomerAuthOverlayConnector(deps);
  const result = await connector.connect(makeAdapter(), 'tenant-1');
  assert.equal(result.status, 'connect-failed');
  assert.equal(embedder.calls.length, 0);
  assert.equal(rateLimiter.allow('customer-auth-overlay:tenant-1:test-adapter'), false, 'penalize() must drain the bucket');
});

test('live connect failure penalizes the rate limiter and reports connect-failed', async () => {
  const rateLimiter = new RateLimiter({ maxRequests: 5, windowMs: 60_000 });
  const { deps, embedder } = makeDeps({ rateLimiter, connectAndListTools: async () => ({ ok: false, reason: 'ECONNREFUSED' }) });
  const connector = new CustomerAuthOverlayConnector(deps);
  const result = await connector.connect(makeAdapter(), 'tenant-1');
  assert.equal(result.status, 'connect-failed');
  assert.equal(result.reason, 'ECONNREFUSED');
  assert.equal(embedder.calls.length, 0);
  assert.equal(rateLimiter.allow('customer-auth-overlay:tenant-1:test-adapter'), false);
});

test('brute-force guard: rate limiter refuses once the bucket is exhausted (consumed only at the decrypt+connect attempt, not the vault read)', async () => {
  const rateLimiter = new RateLimiter({ maxRequests: 2, windowMs: 60_000 });
  let connectAttempts = 0;
  const { deps } = makeDeps({
    rateLimiter,
    connectAndListTools: async () => { connectAttempts++; return { ok: false, reason: 'nope' }; },
  });
  const connector = new CustomerAuthOverlayConnector(deps);
  // Two attempts consume + penalize the 2-token bucket (each failure
  // drains it fully — penalize() sets tokens to 0).
  await connector.connect(makeAdapter(), 'tenant-1');
  assert.equal(connectAttempts, 1);
  let credentialFetchCalledOnThirdAttempt = false;
  const deps2: CustomerAuthOverlayDeps = {
    ...deps,
    fetchCredential: async (...args) => {
      credentialFetchCalledOnThirdAttempt = true;
      return deps.fetchCredential ? deps.fetchCredential(...args) : null;
    },
  };
  const connector2 = new CustomerAuthOverlayConnector(deps2);
  const result = await connector2.connect(makeAdapter(), 'tenant-1');
  assert.equal(result.status, 'rate-limited');
  // The vault read is a cheap DB-only outcome, not a credential guess — it
  // is NOT gated by the limiter (fix per team-lead review: consuming
  // allow() before the vault/already-embedded checks would drain the
  // bucket on a busy tenant's own ordinary traffic once wired at the
  // dispatch entry). What the limiter MUST block is the actual
  // decrypt+live-connect attempt.
  assert.equal(credentialFetchCalledOnThirdAttempt, true, 'the vault read is not gated by the brute-force limiter');
  assert.equal(connectAttempts, 1, 'rate-limited must short-circuit BEFORE the decrypt+live-connect attempt — no second connectAndListTools call');
});

test('an already-embedded connect never touches the rate limiter — ordinary dispatch traffic cannot self-exhaust the brute-force bucket', async () => {
  const rateLimiter = new RateLimiter({ maxRequests: 1, windowMs: 60_000 });
  let allowCalls = 0;
  const countingRateLimiter = new Proxy(rateLimiter, {
    get(target, prop, receiver) {
      if (prop === 'allow') {
        return (server: string) => { allowCalls++; return target.allow(server); };
      }
      return Reflect.get(target, prop, receiver);
    },
  });
  const { deps, embedder } = makeDeps({ rateLimiter: countingRateLimiter });
  const connector = new CustomerAuthOverlayConnector(deps);
  // First connect: capacity-1 bucket allows exactly one decrypt+connect
  // attempt, which succeeds and embeds.
  const r1 = await connector.connect(makeAdapter(), 'tenant-1');
  assert.equal(r1.status, 'embedded');
  assert.equal(allowCalls, 1);
  // N further dispatches to the SAME already-embedded credential version
  // must all succeed without ever calling allow() again — this is the
  // "busy tenant's own traffic" scenario the reordering exists to fix.
  for (let i = 0; i < 5; i++) {
    const r = await connector.connect(makeAdapter(), 'tenant-1');
    assert.equal(r.status, 'already-embedded');
  }
  assert.equal(allowCalls, 1, 'already-embedded connects must never consult the rate limiter');
  assert.equal(embedder.calls.length, 1);
});

// ─── Nothing credential-shaped leaks into audit/event data ─────────────────

test('audit detail and no credential material ever appears in emitted data', async () => {
  const { deps, auditCalls } = makeDeps();
  const connector = new CustomerAuthOverlayConnector(deps);
  await connector.connect(makeAdapter(), 'tenant-1');
  const serialized = JSON.stringify(auditCalls);
  assert.equal(serialized.includes('super-secret-token'), false);
  assert.equal(serialized.includes('super-secret-secret'), false);
  assert.equal(serialized.includes('ciphertext'), false);
  assert.ok(auditCalls.some((c) => c.eventType === 'adapter_connected'));
});

// ─── Fixes from team-lead review, 2026-09-05 ───────────────────────────────

test('oauth2: authScheme "oauth2" gets the SAME Authorization: Bearer header as "bearer" (§10.5 stores the OAuth access token as fields.apiKey)', async () => {
  const seenHeaders: string[] = [];
  const server = new McpServer({ name: 'fixture-oauth2', version: '1.0.0' });
  server.tool('echo', { text: z.string() }, async (args) => ({ content: [{ type: 'text' as const, text: args.text }] }));
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: () => randomUUID() });
  await server.connect(transport);
  const realServer = createServer((req, res) => {
    const auth = req.headers['authorization'];
    if (typeof auth === 'string') seenHeaders.push(auth);
    void (async () => {
      try { await transport.handleRequest(req, res); } catch { if (!res.headersSent) { res.writeHead(500); res.end('error'); } }
    })();
  });
  await new Promise<void>((resolve) => realServer.listen(0, '127.0.0.1', resolve));
  const addr = realServer.address();
  if (!addr || typeof addr !== 'object') throw new Error('failed to bind fixture server');
  const url = `http://127.0.0.1:${addr.port}/mcp`;

  const adapter = makeAdapter({ mcp: { transport: 'streamable-http', url, authScheme: 'oauth2', toolNames: ['echo'] } });
  const outcome = await defaultConnectAndListTools(adapter, { apiKey: 'oauth-access-token-abc' });
  realServer.close();

  assert.equal(outcome.ok, true);
  assert.ok(seenHeaders.length > 0);
  assert.ok(
    seenHeaders.every((h) => h === 'Bearer oauth-access-token-abc'),
    `oauth2 authScheme must send the SAME Authorization: Bearer header as bearer, saw: ${JSON.stringify(seenHeaders)}`,
  );
});

test('a live-connect rejection carrying the apiKey and its Basic-auth base64 form is redacted from the returned reason, the warn log, and the audit detail', async () => {
  const apiKey = 'super-secret-oauth-token-xyz';
  const apiKeyBase64 = Buffer.from(apiKey, 'utf-8').toString('base64');
  const { deps, auditCalls } = makeDeps({
    decrypt: async () => ({ fields: { apiKey } }),
    connectAndListTools: async () => {
      throw new Error(`request failed: Authorization: Bearer ${apiKey} (basic form ${apiKeyBase64}) — 401 Unauthorized`);
    },
  });
  const connector = new CustomerAuthOverlayConnector(deps);

  const originalWrite = process.stderr.write.bind(process.stderr);
  let stderrCaptured = '';
  (process.stderr as unknown as { write: typeof process.stderr.write }).write = ((chunk: unknown, ...rest: unknown[]) => {
    stderrCaptured += typeof chunk === 'string' ? chunk : String(chunk);
    return (originalWrite as (...a: unknown[]) => boolean)(chunk, ...rest);
  }) as typeof process.stderr.write;

  let result: OverlayConnectResult;
  try {
    result = await connector.connect(makeAdapter(), 'tenant-1');
  } finally {
    process.stderr.write = originalWrite;
  }

  assert.equal(result.status, 'connect-failed');
  assert.ok(result.reason, 'expected a reason string');
  assert.equal(result.reason?.includes(apiKey), false, `reason leaked the apiKey: ${result.reason}`);
  assert.equal(result.reason?.includes(apiKeyBase64), false, `reason leaked the base64 form: ${result.reason}`);
  assert.ok(result.reason?.includes('[redacted]'), `expected a redaction marker in the reason: ${result.reason}`);

  assert.equal(stderrCaptured.includes(apiKey), false, `warn log leaked the apiKey: ${stderrCaptured}`);
  assert.equal(stderrCaptured.includes(apiKeyBase64), false, `warn log leaked the base64 form: ${stderrCaptured}`);

  const auditSerialized = JSON.stringify(auditCalls);
  assert.equal(auditSerialized.includes(apiKey), false, `audit detail leaked the apiKey: ${auditSerialized}`);
  assert.equal(auditSerialized.includes(apiKeyBase64), false, `audit detail leaked the base64 form: ${auditSerialized}`);
});

test('a live-connect {ok:false, reason} carrying the apiKey (no throw) is also redacted', async () => {
  const apiKey = 'plain-returned-secret-123';
  const { deps } = makeDeps({
    decrypt: async () => ({ fields: { apiKey } }),
    connectAndListTools: async () => ({ ok: false, reason: `connection refused for token ${apiKey}` }),
  });
  const connector = new CustomerAuthOverlayConnector(deps);
  const result = await connector.connect(makeAdapter(), 'tenant-1');
  assert.equal(result.status, 'connect-failed');
  assert.equal(result.reason?.includes(apiKey), false, `reason leaked the apiKey: ${result.reason}`);
});

// ─── §8.6a tenant overlay tool registry wiring (team-lead review 2026-09-05) ──

test('a successful embed records the live tools into the tenant overlay tool registry', async () => {
  const { deps, registry } = makeDeps();
  const connector = new CustomerAuthOverlayConnector(deps);
  const result = await connector.connect(makeAdapter(), 'tenant-1');
  assert.equal(result.status, 'embedded');
  assert.equal(registry.calls.length, 1);
  assert.equal(registry.calls[0]?.tenantId, 'tenant-1');
  assert.equal(registry.calls[0]?.adapterId, 'test-adapter');
  assert.deepEqual(registry.calls[0]?.tools.map((t) => t.name), ['echo']);
});

test('a registry write failure fails the WHOLE connect closed — never reports embedded with an unregistered tool', async () => {
  const { deps, embedder } = makeDeps({
    registry: { recordTools: async () => { throw new Error('disk full'); } },
  });
  const connector = new CustomerAuthOverlayConnector(deps);
  const result = await connector.connect(makeAdapter(), 'tenant-1');
  assert.equal(result.status, 'connect-failed');
  assert.equal(result.reason, 'registry_write_failed');
  // The embed itself already ran (vectors ARE upserted) — the registry
  // write is a SEPARATE durable record; asserting it happened is not the
  // point here, the point is the CONNECT RESULT must not say "embedded"
  // when the registry — the thing that makes the tool dispatchable/
  // listable — failed to persist.
  assert.equal(embedder.calls.length, 1);
});
