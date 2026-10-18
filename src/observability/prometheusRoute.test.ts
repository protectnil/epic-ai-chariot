/**
 * CHARIOT::§16.3 (CHARIOT-SPEC.md:1375, rulings item 91(3)) — "GET /metrics
 * (Prometheus format, when the Prometheus exporter is enabled)." Ruling:
 * mounted only when CHARIOT_PROMETHEUS_EXPORTER=1 AND requiring a bearer
 * token CHARIOT_METRICS_TOKEN; enabled without a token is a startup
 * refusal.
 *
 * No supertest in this repo (see admin.audit-logs-export.test.ts's own
 * header comment) — this file spins up a real http.Server wrapping the
 * express Router and hits it with the built-in `fetch`, which is a
 * dependency-free real integration test, not a mock.
 *
 * Run (after tsc): node --test dist/observability/prometheusRoute.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import express from 'express';
import {
  assertPrometheusExporterConfigValid,
  isPrometheusExporterEnabled,
  createPrometheusMetricsRouter,
  formatPrometheusMetrics,
} from './prometheusRoute.js';
import { ChariotMetrics } from './metrics.js';

test('§16.3: isPrometheusExporterEnabled() is true only for the literal string "1"', () => {
  assert.equal(isPrometheusExporterEnabled({ CHARIOT_PROMETHEUS_EXPORTER: '1' } as NodeJS.ProcessEnv), true);
  assert.equal(isPrometheusExporterEnabled({ CHARIOT_PROMETHEUS_EXPORTER: 'true' } as NodeJS.ProcessEnv), false);
  assert.equal(isPrometheusExporterEnabled({} as NodeJS.ProcessEnv), false);
});

test('§16.3: assertPrometheusExporterConfigValid() throws when the exporter is enabled with no token (startup refusal)', () => {
  assert.throws(() => assertPrometheusExporterConfigValid({ CHARIOT_PROMETHEUS_EXPORTER: '1' } as NodeJS.ProcessEnv));
});

test('§16.3: assertPrometheusExporterConfigValid() does not throw when the exporter is enabled WITH a token', () => {
  assert.doesNotThrow(() => assertPrometheusExporterConfigValid({ CHARIOT_PROMETHEUS_EXPORTER: '1', CHARIOT_METRICS_TOKEN: 'tok' } as NodeJS.ProcessEnv));
});

test('§16.3: assertPrometheusExporterConfigValid() does not throw when the exporter is disabled, token or not', () => {
  assert.doesNotThrow(() => assertPrometheusExporterConfigValid({} as NodeJS.ProcessEnv));
});

test('§16.3::1: formatPrometheusMetrics() shape covers autonomy byTier and tokenUsageByAdapter as labeled series', () => {
  const m = new ChariotMetrics();
  m.setTokenUsageSource({ getTokenUsageByAdapter: () => ({ slack: { tokens: 42, costUsd: 0.01 } }) });
  const text = formatPrometheusMetrics(m.getSummary());
  assert.match(text, /chariot_autonomy_pending_approvals \d+/);
  assert.match(text, /chariot_autonomy_decisions_total\{tier="auto"\} 0/);
  assert.match(text, /chariot_token_usage_total\{adapter="slack"\} 42/);
});

async function withServer(router: express.Router, fn: (baseUrl: string) => Promise<void>): Promise<void> {
  const app = express();
  app.use(router);
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  try {
    const address = server.address();
    if (address === null || typeof address === 'string') throw new Error('no port');
    await fn(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

test('§16.3 route: GET /metrics with no Authorization header -> 401', async () => {
  const originalToken = process.env.CHARIOT_METRICS_TOKEN;
  process.env.CHARIOT_METRICS_TOKEN = 'secret-token';
  try {
    const router = createPrometheusMetricsRouter(() => new ChariotMetrics());
    await withServer(router, async (base) => {
      const res = await fetch(`${base}/metrics`);
      assert.equal(res.status, 401);
    });
  } finally {
    if (originalToken === undefined) delete process.env.CHARIOT_METRICS_TOKEN;
    else process.env.CHARIOT_METRICS_TOKEN = originalToken;
  }
});

test('§16.3 route: GET /metrics with the wrong bearer token -> 401', async () => {
  const originalToken = process.env.CHARIOT_METRICS_TOKEN;
  process.env.CHARIOT_METRICS_TOKEN = 'secret-token';
  try {
    const router = createPrometheusMetricsRouter(() => new ChariotMetrics());
    await withServer(router, async (base) => {
      const res = await fetch(`${base}/metrics`, { headers: { Authorization: 'Bearer wrong-token' } });
      assert.equal(res.status, 401);
    });
  } finally {
    if (originalToken === undefined) delete process.env.CHARIOT_METRICS_TOKEN;
    else process.env.CHARIOT_METRICS_TOKEN = originalToken;
  }
});

test('§16.3 route: GET /metrics with the correct bearer token -> 200, Prometheus text body', async () => {
  const originalToken = process.env.CHARIOT_METRICS_TOKEN;
  process.env.CHARIOT_METRICS_TOKEN = 'secret-token';
  try {
    const router = createPrometheusMetricsRouter(() => new ChariotMetrics());
    await withServer(router, async (base) => {
      const res = await fetch(`${base}/metrics`, { headers: { Authorization: 'Bearer secret-token' } });
      assert.equal(res.status, 200);
      assert.match(res.headers.get('content-type') ?? '', /text\/plain/);
      const body = await res.text();
      assert.match(body, /chariot_sessions_created_total 0/);
    });
  } finally {
    if (originalToken === undefined) delete process.env.CHARIOT_METRICS_TOKEN;
    else process.env.CHARIOT_METRICS_TOKEN = originalToken;
  }
});

test('§16.3 route: GET /metrics when no ChariotMetrics instance is available -> 503', async () => {
  const originalToken = process.env.CHARIOT_METRICS_TOKEN;
  process.env.CHARIOT_METRICS_TOKEN = 'secret-token';
  try {
    const router = createPrometheusMetricsRouter(() => undefined);
    await withServer(router, async (base) => {
      const res = await fetch(`${base}/metrics`, { headers: { Authorization: 'Bearer secret-token' } });
      assert.equal(res.status, 503);
    });
  } finally {
    if (originalToken === undefined) delete process.env.CHARIOT_METRICS_TOKEN;
    else process.env.CHARIOT_METRICS_TOKEN = originalToken;
  }
});
