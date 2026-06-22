/**
 * @epicai/chariot — Run Telemetry
 * Collects a concise, human-readable summary of one agent run.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { randomUUID } from 'node:crypto';
import type { StreamEvent, RunTiming } from '../types/index.js';
import type { LogEntry, LogLevel } from './EventEmitter.js';

export interface RunTelemetryStep {
  type: StreamEvent['type'];
  timestamp: Date;
  data: StreamEvent['data'];
}

export interface RunTelemetryLog {
  level: LogLevel;
  timestamp: Date;
  message: string;
  layer?: string;
  data?: Record<string, unknown>;
}

export interface RunTelemetrySnapshot {
  runId: string;
  startedAt: Date;
  finishedAt: Date | null;
  durationMs: number;
  eventCounts: Record<StreamEvent['type'], number>;
  logCounts: Record<LogLevel, number>;
  recentSteps: RunTelemetryStep[];
  recentLogs: RunTelemetryLog[];
  lastEventType: StreamEvent['type'] | null;
  lastError: string | null;
}

interface TelemetrySource {
  onEvent(callback: (event: StreamEvent) => void): unknown;
  offEvent?(callback: (event: StreamEvent) => void): unknown;
  onLog(callback: (entry: LogEntry) => void): unknown;
  offLog?(callback: (entry: LogEntry) => void): unknown;
}

export interface RunTelemetryCollectorOptions {
  runId?: string;
  startedAt?: Date;
  maxRecentEntries?: number;
}

const EVENT_TYPES: StreamEvent['type'][] = [
  'plan',
  'action',
  'approval-needed',
  'result',
  'memory',
  'narrative',
  'source-attribution',
  'no-narrative',
  'error',
  'done',
  'selection-probe',
  'drift-detected',
  'step-trace',
  'tool-call-retry',
  'tool-error-classified',
  'policy-decision',
  'parameter-validation-rejected',
  'approval-required',
  'sub-agent-spawn',
  'shortlist-token-cost',
  'context-budget-exceeded',
  'probe-decision',
  'steering-applied',
];

const LOG_LEVELS: LogLevel[] = ['debug', 'info', 'warn', 'error'];

function createEventCounts(): Record<StreamEvent['type'], number> {
  return {
    plan: 0,
    action: 0,
    'approval-needed': 0,
    result: 0,
    memory: 0,
    narrative: 0,
    'source-attribution': 0,
    'no-narrative': 0,
    error: 0,
    done: 0,
    'selection-probe': 0,
    'drift-detected': 0,
    'step-trace': 0,
    'tool-call-retry': 0,
    'tool-error-classified': 0,
    'policy-decision': 0,
    'parameter-validation-rejected': 0,
    'approval-required': 0,
    'sub-agent-spawn': 0,
    'shortlist-token-cost': 0,
    'context-budget-exceeded': 0,
    'probe-decision': 0,
    'steering-applied': 0,
  };
}

function createLogCounts(): Record<LogLevel, number> {
  return {
    debug: 0,
    info: 0,
    warn: 0,
    error: 0,
  };
}

function cloneData(value: unknown): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return value;
  try {
    return structuredClone(value);
  } catch {
    return JSON.parse(JSON.stringify(value)) as unknown;
  }
}

const REDACT_FIELD_KEY = /(authorization|api[_-]?key|api[_-]?secret|password|passwd|secret|token|bearer|credential|cookie|set[_-]?cookie|client[_-]?secret|private[_-]?key)/i;

function summarizeStepData(data: unknown): string {
  if (data === null || data === undefined) return '';
  if (typeof data === 'string') return data.length > 200 ? data.slice(0, 200) + '…' : data;
  if (typeof data === 'number' || typeof data === 'boolean') return String(data);
  if (typeof data !== 'object') return '';
  const projected: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(data as Record<string, unknown>)) {
    if (REDACT_FIELD_KEY.test(k)) {
      projected[k] = '<REDACTED>';
    } else if (typeof v === 'string') {
      projected[k] = v.length > 120 ? v.slice(0, 120) + '…' : v;
    } else if (typeof v === 'number' || typeof v === 'boolean' || v === null) {
      projected[k] = v;
    } else {
      // For nested objects, emit shape only.
      projected[k] = Array.isArray(v) ? `[array len=${v.length}]` : `[object keys=${Object.keys(v as object).length}]`;
    }
  }
  return JSON.stringify(projected);
}

/**
 * Collects and formats run-level telemetry from StreamEvents and structured logs.
 */
export class RunTelemetryCollector {
  private readonly runId: string;
  private readonly startedAt: Date;
  private readonly maxRecentEntries: number;
  private finishedAt: Date | null = null;
  private readonly eventCounts = createEventCounts();
  private readonly logCounts = createLogCounts();
  private readonly recentSteps: RunTelemetryStep[] = [];
  private readonly recentLogs: RunTelemetryLog[] = [];
  private lastEventType: StreamEvent['type'] | null = null;
  private lastError: string | null = null;

  constructor(options: RunTelemetryCollectorOptions = {}) {
    this.runId = options.runId ?? randomUUID();
    this.startedAt = options.startedAt ?? new Date();
    this.maxRecentEntries = options.maxRecentEntries ?? 12;
  }

  recordEvent(event: StreamEvent): void {
    this.eventCounts[event.type] += 1;
    this.lastEventType = event.type;

    if (event.type === 'error') {
      this.lastError = event.data.message;
    }

    if (event.type === 'done') {
      this.finishedAt = event.timestamp;
    }

    this.recentSteps.push({
      type: event.type,
      timestamp: event.timestamp,
      data: cloneData(event.data) as StreamEvent['data'],
    });

    this.trimRecentEntries();
  }

  recordLog(entry: LogEntry): void {
    this.logCounts[entry.level] += 1;

    this.recentLogs.push({
      level: entry.level,
      timestamp: entry.timestamp,
      message: entry.message,
      layer: entry.layer,
      data: entry.data ? cloneData(entry.data) as Record<string, unknown> : undefined,
    });

    this.trimRecentEntries();
  }

  attach(source: TelemetrySource): () => void {
    const eventCallback = (event: StreamEvent) => this.recordEvent(event);
    const logCallback = (entry: LogEntry) => this.recordLog(entry);

    source.onEvent(eventCallback);
    source.onLog(logCallback);

    return () => {
      source.offEvent?.(eventCallback);
      source.offLog?.(logCallback);
    };
  }

  snapshot(): RunTelemetrySnapshot {
    const endTime = this.finishedAt ?? this.recentSteps.at(-1)?.timestamp ?? this.recentLogs.at(-1)?.timestamp ?? this.startedAt;
    const durationMs = Math.max(0, endTime.getTime() - this.startedAt.getTime());

    return {
      runId: this.runId,
      startedAt: this.startedAt,
      finishedAt: this.finishedAt,
      durationMs,
      eventCounts: { ...this.eventCounts },
      logCounts: { ...this.logCounts },
      recentSteps: [...this.recentSteps],
      recentLogs: [...this.recentLogs],
      lastEventType: this.lastEventType,
      lastError: this.lastError,
    };
  }

  format(): string {
    const snapshot = this.snapshot();
    const events = EVENT_TYPES.map(type => `${type}=${snapshot.eventCounts[type]}`).join(' ');
    const logs = LOG_LEVELS.map(level => `${level}=${snapshot.logCounts[level]}`).join(' ');
    // emitting the raw event.data verbatim leaks credentials
    // and PII out through the telemetry surface (operators tail this
    // for debugging). Project to a redacted shape that includes only
    // the type + small structural fields safe for human consumption.
    const steps = snapshot.recentSteps.length > 0
      ? snapshot.recentSteps
          .map(step => `  - [${step.type}] ${summarizeStepData(step.data)}`)
          .join('\n')
      : '  - (none)';
    const logTail = snapshot.recentLogs.length > 0
      ? snapshot.recentLogs
          .map(entry => `  - [${entry.level}] ${entry.layer ?? 'unknown'} ${entry.message}`)
          .join('\n')
      : '  - (none)';

    // Extract timing breakdown from done event if present
    const doneStep = snapshot.recentSteps.find(s => s.type === 'done');
    const timing = doneStep?.data && typeof doneStep.data === 'object' && 'timing' in doneStep.data
      ? (doneStep.data as { timing: RunTiming }).timing
      : null;
    const timingLine = timing
      ? `Timing: retrieval=${timing.retrievalMs}ms orchestrator=${timing.orchestratorMs}ms federation=${timing.federationMs}ms autonomy=${timing.autonomyMs}ms generator=${timing.generatorMs}ms memory=${timing.memoryMs}ms total=${timing.totalMs}ms`
      : `Duration: ${snapshot.durationMs}ms`;

    return [
      `Run ${snapshot.runId}`,
      timingLine,
      `Events: ${events}`,
      `Logs: ${logs}`,
      `Last event: ${snapshot.lastEventType ?? 'none'}`,
      `Last error: ${snapshot.lastError ?? 'none'}`,
      'Recent events:',
      steps,
      'Recent logs:',
      logTail,
    ].join('\n');
  }

  private trimRecentEntries(): void {
    while (this.recentSteps.length > this.maxRecentEntries) {
      this.recentSteps.shift();
    }
    while (this.recentLogs.length > this.maxRecentEntries) {
      this.recentLogs.shift();
    }
  }
}
