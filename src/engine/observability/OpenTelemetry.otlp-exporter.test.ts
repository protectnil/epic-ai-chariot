/**
 * CHARIOT::§8.12::2 — "OpenTelemetry.ts — exports spans to a configurable
 * OTel collector." Defect this catches: this module's own header said
 * "Consumer provides their own OTEL SDK — we just format the data" — no
 * real OTLP transport existed; `createOtlpHttpJsonSpanExporter` is that
 * transport, built on the existing SpanExporter seam, no @opentelemetry
 * dependency.
 *
 * Run (after tsc):
 *   node --test dist/engine/observability/OpenTelemetry.otlp-exporter.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createOtlpHttpJsonSpanExporter, type OTelSpan } from './OpenTelemetry.js';

function sampleSpan(): OTelSpan {
  return {
    traceId: 'a'.repeat(32),
    spanId: 'b'.repeat(16),
    parentSpanId: 'c'.repeat(16),
    operationName: 'epic-ai.action',
    startTime: new Date(1_700_000_000_000),
    endTime: new Date(1_700_000_000_500),
    attributes: { 'epic_ai.tool': 'search_repos', 'epic_ai.duration_ms': 123, 'epic_ai.ok': true },
    events: [{ name: 'retry', timestamp: new Date(1_700_000_000_250), attributes: { 'epic_ai.attempt': 2 } }],
    status: 'OK',
  };
}

test('§8.12::2: OFF when no endpoint is configured (returns null, not a no-op function)', () => {
  const originalEnv = process.env['CHARIOT_OTEL_EXPORTER_OTLP_ENDPOINT'];
  delete process.env['CHARIOT_OTEL_EXPORTER_OTLP_ENDPOINT'];
  try {
    const exporter = createOtlpHttpJsonSpanExporter();
    assert.equal(exporter, null, '"off when unset" — no endpoint configured means no exporter at all');
  } finally {
    if (originalEnv !== undefined) process.env['CHARIOT_OTEL_EXPORTER_OTLP_ENDPOINT'] = originalEnv;
  }
});

test('§8.12::2: POSTs a byte-correct ExportTraceServiceRequest JSON shape to the configured endpoint', async () => {
  const requests: Array<{ url: string; init: RequestInit }> = [];
  const fakeFetch = (async (url: string, init: RequestInit) => {
    requests.push({ url: String(url), init });
    return new Response(null, { status: 200 });
  }) as unknown as typeof fetch;

  const exporter = createOtlpHttpJsonSpanExporter({
    endpoint: 'https://collector.example.com/v1/traces',
    headers: 'x-api-key=secret123,x-tenant=acme',
    fetchImpl: fakeFetch,
    serviceName: 'test-service',
  });
  assert.ok(exporter, 'exporter must be non-null when endpoint is explicitly passed');

  exporter!(sampleSpan());
  // fetch is fired synchronously inside the exporter call; await a tick so
  // the fire-and-forget promise chain runs before we inspect requests[].
  await new Promise((resolve) => setTimeout(resolve, 10));

  assert.equal(requests.length, 1);
  assert.equal(requests[0].url, 'https://collector.example.com/v1/traces');
  assert.equal(requests[0].init.method, 'POST');
  const headers = requests[0].init.headers as Record<string, string>;
  assert.equal(headers['content-type'], 'application/json');
  assert.equal(headers['x-api-key'], 'secret123', 'CHARIOT_OTEL_EXPORTER_OTLP_HEADERS parsed correctly');
  assert.equal(headers['x-tenant'], 'acme');

  const body = JSON.parse(String(requests[0].init.body)) as {
    resourceSpans: Array<{
      resource: { attributes: Array<{ key: string; value: Record<string, unknown> }> };
      scopeSpans: Array<{ spans: Array<Record<string, unknown>> }>;
    }>;
  };
  const resourceSpan = body.resourceSpans[0];
  assert.equal(
    resourceSpan.resource.attributes.find((a) => a.key === 'service.name')?.value.stringValue,
    'test-service',
  );
  const span = resourceSpan.scopeSpans[0].spans[0];
  assert.equal(span['traceId'], 'a'.repeat(32), 'traceId passed through as hex, not re-encoded to base64');
  assert.equal(span['spanId'], 'b'.repeat(16));
  assert.equal(span['parentSpanId'], 'c'.repeat(16));
  assert.equal(span['name'], 'epic-ai.action');
  assert.equal(span['startTimeUnixNano'], '1700000000000000000', 'ms epoch -> ns string');
  assert.equal(span['endTimeUnixNano'], '1700000000500000000');
  assert.equal((span as { status: { code: number } }).status.code, 1, 'OK -> STATUS_CODE_OK (1)');

  const attrs = span['attributes'] as Array<{ key: string; value: Record<string, unknown> }>;
  assert.equal(attrs.find((a) => a.key === 'epic_ai.tool')?.value.stringValue, 'search_repos');
  assert.equal(attrs.find((a) => a.key === 'epic_ai.duration_ms')?.value.intValue, '123');
  assert.equal(attrs.find((a) => a.key === 'epic_ai.ok')?.value.boolValue, true);

  const events = span['events'] as Array<{ name: string; timeUnixNano: string }>;
  assert.equal(events[0].name, 'retry');
  assert.equal(events[0].timeUnixNano, '1700000000250000000');
});

test('§8.12::2: never throws into the run path — a rejecting fetch is swallowed', () => {
  const failingFetch = (() => Promise.reject(new Error('collector unreachable'))) as unknown as typeof fetch;
  const exporter = createOtlpHttpJsonSpanExporter({
    endpoint: 'https://unreachable.example.com/v1/traces',
    fetchImpl: failingFetch,
  });
  assert.ok(exporter);
  assert.doesNotThrow(() => exporter!(sampleSpan()), 'the SpanExporter call itself must never throw synchronously');
});

test('§8.12::2: an error-status span maps to STATUS_CODE_ERROR (2)', async () => {
  const requests: Array<{ init: RequestInit }> = [];
  const fakeFetch = (async (_url: string, init: RequestInit) => {
    requests.push({ init });
    return new Response(null, { status: 200 });
  }) as unknown as typeof fetch;

  const exporter = createOtlpHttpJsonSpanExporter({ endpoint: 'https://x.example.com', fetchImpl: fakeFetch });
  exporter!({ ...sampleSpan(), status: 'ERROR' });
  await new Promise((resolve) => setTimeout(resolve, 10));

  const body = JSON.parse(String(requests[0].init.body)) as { resourceSpans: Array<{ scopeSpans: Array<{ spans: Array<{ status: { code: number } }> }> }> };
  assert.equal(body.resourceSpans[0].scopeSpans[0].spans[0].status.code, 2);
});
