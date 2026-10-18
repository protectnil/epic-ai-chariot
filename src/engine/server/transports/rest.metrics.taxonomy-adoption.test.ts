/**
 * CHARIOT::§16.3 (CHARIOT-SPEC.md:1375, rulings item 91(3)/105) — "GET
 * /metrics (Prometheus format, when the Prometheus exporter is enabled)"
 * served on the plain node:http REST transport too, so a non-enterprise
 * (single-user) install with the exporter flag set still has the
 * endpoint — same bearer gate (CHARIOT_METRICS_TOKEN, independent of
 * CHARIOT_REST_TOKEN) and startup refusal as the Express-based
 * prometheusRoute.ts.
 *
 * Real `http.Server` via `bindRest()` + built-in `fetch` — same pattern
 * as rest.timing-safe-bearer.test.ts (this repo's established
 * REST-transport test fixture) and prometheusRoute.test.ts.
 *
 * Run (after tsc): node --test dist/engine/server/transports/rest.metrics.taxonomy-adoption.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { bindRest } from './rest.js';
import { ChariotMetrics } from '../../../observability/metrics.js';
import type { ChariotState } from '../ChariotState.js';
import type { TransportHandle } from '../TransportHandle.js';

function makeMinimalState(withMetrics: boolean): ChariotState {
  return {
    allAdapters: [],
    adapterById: new Map(),
    configuredAdapterIds: new Set(),
    credentials: {},
    fullCatalogFilter: { select: async () => [] },
    toolPreFilter: { select: async () => [] },
    getConfiguredAdapters: () => [],
    loadedAt: new Date(),
    chariotMetrics: withMetrics ? new ChariotMetrics() : undefined,
  } as unknown as ChariotState;
}

interface EnvSnapshot { [k: string]: string | undefined }

function snapshotEnv(keys: string[]): EnvSnapshot {
  const s: EnvSnapshot = {};
  for (const k of keys) s[k] = process.env[k];
  return s;
}

function restoreEnv(snapshot: EnvSnapshot): void {
  for (const [k, v] of Object.entries(snapshot)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
}

const ENV_KEYS = ['CHARIOT_REST_TOKEN', 'CHARIOT_ALLOW_UNAUTHENTICATED_REST', 'CHARIOT_PROMETHEUS_EXPORTER', 'CHARIOT_METRICS_TOKEN'];

async function withServer(
  withMetrics: boolean,
  run: (baseUrl: string) => Promise<void>,
): Promise<void> {
  const snapshot = snapshotEnv(ENV_KEYS);
  process.env.CHARIOT_ALLOW_UNAUTHENTICATED_REST = 'true';
  delete process.env.CHARIOT_REST_TOKEN;
  process.env.CHARIOT_PROMETHEUS_EXPORTER = '1';
  process.env.CHARIOT_METRICS_TOKEN = 'test-metrics-token';
  let handle: TransportHandle | undefined;
  try {
    handle = await bindRest(makeMinimalState(withMetrics), 0, () => 'local');
    await run(`http://127.0.0.1:${handle.port}`);
  } finally {
    if (handle) await handle.close();
    restoreEnv(snapshot);
  }
}

test('§16.3 REST /metrics: exporter disabled (flag unset) -> 404', async () => {
  const snapshot = snapshotEnv(ENV_KEYS);
  process.env.CHARIOT_ALLOW_UNAUTHENTICATED_REST = 'true';
  delete process.env.CHARIOT_REST_TOKEN;
  delete process.env.CHARIOT_PROMETHEUS_EXPORTER;
  delete process.env.CHARIOT_METRICS_TOKEN;
  let handle: TransportHandle | undefined;
  try {
    handle = await bindRest(makeMinimalState(true), 0, () => 'local');
    const res = await fetch(`http://127.0.0.1:${handle.port}/metrics`);
    assert.equal(res.status, 404);
  } finally {
    if (handle) await handle.close();
    restoreEnv(snapshot);
  }
});

test('§16.3 REST /metrics: exporter enabled, no Authorization header -> 401', async () => {
  await withServer(true, async (base) => {
    const res = await fetch(`${base}/metrics`);
    assert.equal(res.status, 401);
  });
});

test('§16.3 REST /metrics: wrong bearer token (even a VALID CHARIOT_REST_TOKEN-shaped one) -> 401 (independent token spaces)', async () => {
  await withServer(true, async (base) => {
    const res = await fetch(`${base}/metrics`, { headers: { Authorization: 'Bearer some-other-token' } });
    assert.equal(res.status, 401);
  });
});

test('§16.3 REST /metrics: correct CHARIOT_METRICS_TOKEN -> 200, Prometheus text body', async () => {
  await withServer(true, async (base) => {
    const res = await fetch(`${base}/metrics`, { headers: { Authorization: 'Bearer test-metrics-token' } });
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-type') ?? '', /text\/plain/);
    const body = await res.text();
    assert.match(body, /chariot_sessions_created_total 0/);
  });
});

test('§16.3 REST /metrics: no ChariotMetrics instance on state -> 503', async () => {
  await withServer(false, async (base) => {
    const res = await fetch(`${base}/metrics`, { headers: { Authorization: 'Bearer test-metrics-token' } });
    assert.equal(res.status, 503);
  });
});

test('§16.3 REST: bindRest() throws when the exporter flag is set with no CHARIOT_METRICS_TOKEN (startup refusal, independent of setup.ts)', async () => {
  const snapshot = snapshotEnv(ENV_KEYS);
  process.env.CHARIOT_ALLOW_UNAUTHENTICATED_REST = 'true';
  delete process.env.CHARIOT_REST_TOKEN;
  process.env.CHARIOT_PROMETHEUS_EXPORTER = '1';
  delete process.env.CHARIOT_METRICS_TOKEN;
  try {
    await assert.rejects(() => bindRest(makeMinimalState(true), 0, () => 'local'));
  } finally {
    restoreEnv(snapshot);
  }
});
