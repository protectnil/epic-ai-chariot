/**
 * Regression eval: the backend health probe is uniform on GET /v1/models (§8.10).
 *
 * The defect this exists to catch: probeBackend() special-cased ollama-type
 * backends to `${url}/api/version` and skipped modelIds collection for them.
 * §8.10 ("GET /v1/models against each backend; healthy if 200 within five
 * seconds") mandates /v1/models for EVERY backend. An ollama backend was
 * therefore probed off-spec and registered with an empty model list.
 *
 * The probe is driven through the public discover() path against a real local
 * HTTP stub, so the assertions observe the actual request the code makes — not
 * a mock of the code's intent.
 *
 * Run (after tsc):
 *   node --test dist/engine/gateway/BackendRegistry.probe.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { BackendRegistry } from './BackendRegistry.js';
import { ControlPlane } from './ControlPlane.js';
import type { GatewayConfig, BackendType } from './types.js';

// ── a stub backend that records every path it is asked for ───────────────────

interface Stub {
  server: Server;
  url: string;
  paths: string[];
  close: () => Promise<void>;
}

function startStub(handler: (path: string) => { status: number; body: string }): Promise<Stub> {
  const paths: string[] = [];
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      paths.push(req.url ?? '');
      const { status, body } = handler(req.url ?? '');
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(body);
    });
    server.listen(0, '127.0.0.1', () => {
      const port = (server.address() as AddressInfo).port;
      resolve({
        server,
        url: `http://127.0.0.1:${port}`,
        paths,
        close: () => new Promise((r) => server.close(() => r())),
      });
    });
  });
}

function cfg(url: string, type: BackendType): GatewayConfig {
  return {
    port: 0,
    backends: [{ url, type, name: `stub-${type}` }],
    routingStrategy: 'round-robin',
    ollamaShim: { enabled: false, deprecationWindowEnd: '2026-12-31', logMigrationHints: false },
    healthCheck: {
      intervalMs: 60_000,
      timeoutMs: 2_000,
      unhealthyThreshold: 3,
      degradedLatencyMultiplier: 3,
    },
    autoDiscover: false,
    shutdownDrainMs: 0,
    rateLimitPerMinute: 100,
    corsOrigins: [],
  } as unknown as GatewayConfig;
}

// ── the regression this file exists to catch ─────────────────────────────────

test('probe: an ollama backend is health-checked on /v1/models, never /api/version', async () => {
  const stub = await startStub((path) => {
    if (path === '/v1/models') return { status: 200, body: JSON.stringify({ data: [{ id: 'llama3' }] }) };
    // /api/version would 200 on a real ollama — must NOT be what we hit.
    if (path === '/api/version') return { status: 200, body: JSON.stringify({ version: '0.1.0' }) };
    return { status: 404, body: '{}' };
  });
  try {
    const cp = new ControlPlane();
    await cp.connect();
    const reg = new BackendRegistry(cp, cfg(stub.url, 'ollama'));
    await reg.discover();

    assert.ok(
      stub.paths.includes('/v1/models'),
      'the probe MUST request /v1/models (§8.10) for an ollama backend',
    );
    assert.ok(
      !stub.paths.includes('/api/version'),
      'the probe MUST NOT fall back to the off-spec /api/version for ollama',
    );

    const health = await cp.getBackendHealth(stub.url);
    assert.ok(health, 'the backend must be recorded');
    assert.equal(health.status, 'healthy', '200 within timeout is healthy');
    assert.deepEqual(
      health.modelIds,
      ['llama3'],
      'modelIds must be collected for ollama too — the old path left them empty',
    );
  } finally {
    await stub.close();
  }
});

test('probe: a malformed /v1/models body does not crash and yields empty modelIds', async () => {
  const stub = await startStub((path) =>
    path === '/v1/models'
      ? { status: 200, body: 'not json at all' }
      : { status: 404, body: '{}' },
  );
  try {
    const cp = new ControlPlane();
    await cp.connect();
    const reg = new BackendRegistry(cp, cfg(stub.url, 'vllm'));
    await reg.discover();

    const health = await cp.getBackendHealth(stub.url);
    assert.ok(health, 'backend recorded despite unparseable model list');
    assert.equal(health.status, 'healthy', 'a 200 is healthy even if the body is junk');
    assert.deepEqual(health.modelIds, [], 'unparseable body → empty modelIds, no throw');
  } finally {
    await stub.close();
  }
});

test('probe: a non-array data field does not throw', async () => {
  const stub = await startStub((path) =>
    path === '/v1/models'
      ? { status: 200, body: JSON.stringify({ data: { not: 'an array' } }) }
      : { status: 404, body: '{}' },
  );
  try {
    const cp = new ControlPlane();
    await cp.connect();
    const reg = new BackendRegistry(cp, cfg(stub.url, 'vllm'));
    await reg.discover();

    const health = await cp.getBackendHealth(stub.url);
    assert.ok(health, 'backend recorded');
    assert.deepEqual(health.modelIds, [], 'a non-array data shape must not crash the probe');
  } finally {
    await stub.close();
  }
});

test('probe: a backend that only serves /api/version (no /v1/models) is unhealthy', async () => {
  // The deliberate consequence of the §8.10 mandate: a legacy ollama-only
  // deployment that lacks the OpenAI-compatible surface is now unhealthy.
  const stub = await startStub((path) =>
    path === '/api/version'
      ? { status: 200, body: JSON.stringify({ version: '0.1.0' }) }
      : { status: 404, body: '{}' },
  );
  try {
    const cp = new ControlPlane();
    await cp.connect();
    const reg = new BackendRegistry(cp, cfg(stub.url, 'ollama'));
    await reg.discover();

    const health = await cp.getBackendHealth(stub.url);
    assert.ok(health, 'an unreachable-on-/v1/models backend is still recorded');
    assert.equal(
      health.status,
      'unhealthy',
      'a 404 on /v1/models is unhealthy even though /api/version would 200 — ' +
        'this is the documented cost of the spec mandate, asserted so it is a choice, not a surprise',
    );
  } finally {
    await stub.close();
  }
});
