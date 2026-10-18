/**
 * @epicai/chariot — OpenTelemetry Integration
 * Converts StreamEvents and LogEntries into OTEL-compatible spans.
 * Consumer provides their own OTEL SDK — we just format the data.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { randomBytes } from 'node:crypto';
import type { StreamEvent } from '../types/index.js';
import type { LogEntry, EventCallback, LogCallback } from './EventEmitter.js';

export interface OTelSpan {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  operationName: string;
  startTime: Date;
  endTime?: Date;
  attributes: Record<string, string | number | boolean>;
  events: { name: string; timestamp: Date; attributes?: Record<string, string | number | boolean> }[];
  status: 'OK' | 'ERROR' | 'UNSET';
}

export type SpanExporter = (span: OTelSpan) => void;

/**
 * Creates an EventCallback that converts StreamEvents into OTEL spans.
 * The consumer provides a SpanExporter that sends spans to their OTEL backend
 * (Grafana, Datadog, Jaeger, etc.).
 */
export function createOTelEventCallback(exporter: SpanExporter, traceId?: string): EventCallback {
  const activeTraceId = traceId ?? generateTraceId();
  let rootSpanId: string | null = null;
  const spanStartTimes = new Map<string, Date>();

  return (event: StreamEvent) => {
    const spanId = generateId();

    if (event.type === 'plan') {
      rootSpanId = spanId;
      spanStartTimes.set('root', event.timestamp);
    }

    const span: OTelSpan = {
      traceId: activeTraceId,
      spanId,
      parentSpanId: rootSpanId ?? undefined,
      operationName: `epic-ai.${event.type}`,
      startTime: event.timestamp,
      attributes: {
        'epic_ai.event_type': event.type,
        ...flattenData(event.data),
      },
      events: [],
      status: event.type === 'error' ? 'ERROR' : 'OK',
    };

    if (event.type === 'done') {
      const rootStart = spanStartTimes.get('root');
      if (rootStart) {
        span.startTime = rootStart;
        span.endTime = event.timestamp;
        span.operationName = 'epic-ai.orchestrator';
      }
    }

    exporter(span);
  };
}

/**
 * Creates a LogCallback that converts LogEntries into OTEL-formatted log records.
 */
export function createOTelLogCallback(exporter: (record: OTelLogRecord) => void): LogCallback {
  return (entry: LogEntry) => {
    exporter({
      timestamp: entry.timestamp,
      severityText: entry.level.toUpperCase(),
      severityNumber: SEVERITY_MAP[entry.level],
      body: entry.message,
      attributes: {
        'epic_ai.layer': entry.layer ?? 'unknown',
        ...flattenData(entry.data ?? {}),
      },
    });
  };
}

export interface OTelLogRecord {
  timestamp: Date;
  severityText: string;
  severityNumber: number;
  body: string;
  attributes: Record<string, string | number | boolean>;
}

const SEVERITY_MAP: Record<string, number> = {
  debug: 5,
  info: 9,
  warn: 13,
  error: 17,
};

/**
 * Generate a cryptographically random trace ID (16 bytes = 32 hex chars).
 */
function generateTraceId(): string {
  return randomBytes(16).toString('hex');
}

/**
 * Generate a cryptographically random span ID (8 bytes = 16 hex chars).
 */
function generateSpanId(): string {
  return randomBytes(8).toString('hex');
}

function generateId(): string {
  return generateSpanId();
}

/**
 * redact credential-shaped keys before any OTEL exporter sees
 * them. Span attributes propagate to whatever backend the operator
 * configured — Datadog, Honeycomb, Grafana, Tempo — and that's a
 * surface secrets MUST NOT leak to. Match keys defensively against
 * the same shape the audit-trail and console-logger sanitizers use.
 */
const REDACT_KEY_PATTERN =
  /(authorization|api[_-]?key|api[_-]?secret|password|passwd|secret|token|bearer|credential|cookie|set[_-]?cookie|client[_-]?secret|private[_-]?key)/i;

function redactValueForKey(key: string, value: string | number | boolean): string | number | boolean {
  if (REDACT_KEY_PATTERN.test(key)) return '<REDACTED>';
  return value;
}

function flattenData(data: Record<string, unknown>): Record<string, string | number | boolean> {
  const result: Record<string, string | number | boolean> = {};
  for (const [key, value] of Object.entries(data)) {
    const attrKey = `epic_ai.${key}`;
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
      result[attrKey] = redactValueForKey(key, value);
    } else if (value !== null && value !== undefined) {
      result[attrKey] = REDACT_KEY_PATTERN.test(key) ? '<REDACTED>' : JSON.stringify(value);
    }
  }
  return result;
}

// ─── OTLP/HTTP JSON exporter (CHARIOT::§8.12::2) ────────────────────────────
//
// "OpenTelemetry.ts — exports spans to a configurable OTel collector." This
// module's own header already says "Consumer provides their own OTEL SDK —
// we just format the data" — this exporter is that missing piece: a real
// `SpanExporter` (the seam already defined above) that actually talks OTLP
// over HTTP, with NO @opentelemetry dependency (grepped `@opentelemetry` in
// src/ + package.json before this change: 0 hits; none added here).
//
// Encodes one `ExportTraceServiceRequest` per span (this module's
// `SpanExporter` type is synchronous, one call per StreamEvent — there is
// no batching boundary to hook without changing that public seam, so each
// span is its own single-span request). traceId/spanId are passed through
// AS HEX (this module already generates them as hex via
// randomBytes(...).toString('hex') — no re-encoding to base64; ruled).

/** OTLP AnyValue — the typed key/value wire shape for span/resource attributes. */
export interface OtlpAnyValue {
  stringValue?: string;
  intValue?: string;
  doubleValue?: number;
  boolValue?: boolean;
}
export interface OtlpKeyValue {
  key: string;
  value: OtlpAnyValue;
}

function toOtlpAnyValue(value: string | number | boolean): OtlpAnyValue {
  if (typeof value === 'string') return { stringValue: value };
  if (typeof value === 'boolean') return { boolValue: value };
  // OTLP JSON encodes int64-typed fields as a decimal STRING (proto3 JSON
  // mapping for int64/fixed64 — a JS `number` cannot safely hold every
  // int64 value). All our attribute numbers are small (durations, counts),
  // but this stays byte-correct for a collector's strict-mode parser.
  return Number.isInteger(value) ? { intValue: String(value) } : { doubleValue: value };
}

function toOtlpAttributes(attrs: Record<string, string | number | boolean>): OtlpKeyValue[] {
  return Object.entries(attrs).map(([key, value]) => ({ key, value: toOtlpAnyValue(value) }));
}

function unixNanoString(date: Date): string {
  // Millisecond-resolution Date -> nanosecond epoch string (OTLP JSON
  // encodes {start,end}TimeUnixNano as decimal strings — uint64, not a JS
  // number). No sub-millisecond clock is available here, so the low 6
  // digits are always zero — honestly representing this module's actual
  // timestamp resolution, not fabricating false precision.
  return `${date.getTime()}000000`;
}

/** OTLP StatusCode: 0=STATUS_CODE_UNSET, 1=STATUS_CODE_OK, 2=STATUS_CODE_ERROR. */
const OTLP_STATUS_CODE: Record<OTelSpan['status'], number> = { UNSET: 0, OK: 1, ERROR: 2 };
/** OTLP SpanKind: 1=SPAN_KIND_INTERNAL — every span this module emits is an internal engine-phase span, never a client/server/producer/consumer RPC boundary. */
const OTLP_SPAN_KIND_INTERNAL = 1;

function buildExportTraceServiceRequest(span: OTelSpan, serviceName: string): Record<string, unknown> {
  return {
    resourceSpans: [
      {
        resource: {
          attributes: toOtlpAttributes({ 'service.name': serviceName }),
        },
        scopeSpans: [
          {
            scope: { name: 'epic-ai-chariot' },
            spans: [
              {
                traceId: span.traceId,
                spanId: span.spanId,
                ...(span.parentSpanId ? { parentSpanId: span.parentSpanId } : {}),
                name: span.operationName,
                kind: OTLP_SPAN_KIND_INTERNAL,
                startTimeUnixNano: unixNanoString(span.startTime),
                endTimeUnixNano: unixNanoString(span.endTime ?? span.startTime),
                attributes: toOtlpAttributes(span.attributes),
                events: span.events.map((e) => ({
                  timeUnixNano: unixNanoString(e.timestamp),
                  name: e.name,
                  attributes: toOtlpAttributes(e.attributes ?? {}),
                })),
                status: { code: OTLP_STATUS_CODE[span.status] },
              },
            ],
          },
        ],
      },
    ],
  };
}

/** Parses the OTel-convention `CHARIOT_OTEL_EXPORTER_OTLP_HEADERS` value:
 * comma-separated `key=value` pairs, URL-decoded (matches the upstream
 * OTel SDK env-var spec for `OTEL_EXPORTER_OTLP_HEADERS`). */
function parseOtlpHeaders(raw: string | undefined): Record<string, string> {
  const headers: Record<string, string> = {};
  if (!raw) return headers;
  for (const pair of raw.split(',')) {
    const eq = pair.indexOf('=');
    if (eq === -1) continue;
    const key = pair.slice(0, eq).trim();
    const value = pair.slice(eq + 1).trim();
    if (!key) continue;
    try {
      headers[key] = decodeURIComponent(value);
    } catch {
      headers[key] = value; // not percent-encoded — use verbatim
    }
  }
  return headers;
}

export interface OtlpHttpJsonExporterOptions {
  /** Defaults to `process.env.CHARIOT_OTEL_EXPORTER_OTLP_ENDPOINT`. Exporter is OFF (createOtlpHttpJsonSpanExporter returns null) when neither is set. */
  endpoint?: string;
  /** Defaults to `process.env.CHARIOT_OTEL_EXPORTER_OTLP_HEADERS`. */
  headers?: string;
  /** Bounded request timeout. Default 5000ms. */
  timeoutMs?: number;
  serviceName?: string;
  /** Test seam — defaults to the global `fetch`. */
  fetchImpl?: typeof fetch;
}

/**
 * CHARIOT::§8.12::2 — builds a real OTLP/HTTP JSON `SpanExporter`. Returns
 * `null` when no endpoint is configured ("off when unset" — ruled): the
 * caller (EpicAI.ts) treats a `null` return as "don't wire OTel at all",
 * matching every other optional-emitter's default-disabled convention in
 * this codebase (TieredAutonomy/RateLimiter's `emitter?`, Orchestrator's
 * `stepEmitter?`).
 *
 * The returned function matches the existing synchronous `SpanExporter`
 * signature and NEVER throws into the caller (fetch is fired and its
 * rejection swallowed) — a collector outage or misconfigured endpoint must
 * never break the orchestrator run path this exporter observes.
 */
export function createOtlpHttpJsonSpanExporter(options: OtlpHttpJsonExporterOptions = {}): SpanExporter | null {
  const endpoint = options.endpoint ?? process.env['CHARIOT_OTEL_EXPORTER_OTLP_ENDPOINT'];
  if (!endpoint || endpoint.trim() === '') return null;

  const extraHeaders = parseOtlpHeaders(options.headers ?? process.env['CHARIOT_OTEL_EXPORTER_OTLP_HEADERS']);
  const timeoutMs = options.timeoutMs ?? 5000;
  const serviceName = options.serviceName ?? 'epic-ai-chariot';
  const doFetch = options.fetchImpl ?? fetch;

  return (span: OTelSpan): void => {
    let body: string;
    try {
      body = JSON.stringify(buildExportTraceServiceRequest(span, serviceName));
    } catch {
      // A span attribute that can't serialize must never break the run path.
      return;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    // Fire-and-forget: SpanExporter is synchronous by contract (called
    // once per StreamEvent from a hot loop path) — this never awaits.
    doFetch(endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...extraHeaders },
      body,
      signal: controller.signal,
    })
      .catch(() => { /* collector unreachable/errored — never throw into the run path */ })
      .finally(() => clearTimeout(timer));
  };
}
