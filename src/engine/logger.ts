/**
 * @epicai/chariot — Logger
 * Thin wrapper over globalThis.console, following the Anthropic/OpenAI SDK pattern.
 * Zero dependencies. Controllable via CHARIOT_LOG_LEVEL env var (CHARIOT::§20::8,
 * the spec-documented Configuration Surface knob — CHARIOT-SPEC.md:1553) or
 * constructor logLevel.
 *
 * Default: 'info' when CHARIOT_LOG_LEVEL is unset (CHARIOT-SPEC.md:1553).
 *
 * Legacy fallback: the undocumented EPICAI_LOG env var (default 'warn') is
 * still honored when CHARIOT_LOG_LEVEL is unset, preserving existing
 * `EPICAI_LOG=debug` payload-verbosity workflows. Set EPICAI_LOG=debug to
 * see full LLM request/response payloads.
 *
 * Optional Loki transport: set EPICAI_LOG_LOKI_URL, EPICAI_LOG_LOKI_USER,
 * and EPICAI_LOG_LOKI_TOKEN to push logs to Grafana Cloud Loki alongside stderr.
 * Logs persist even if the machine is destroyed.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { appendFileSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { LOGS_DIR } from '../cli/paths.js';

export type LogLevel = 'trace' | 'debug' | 'info' | 'warn' | 'error' | 'off';

const LEVEL_ORDER: Record<LogLevel, number> = {
  trace: -1,
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
  off: 4,
};

/**
 * CHARIOT::§20::8 — "WHEN CHARIOT_LOG_LEVEL is set, its value SHALL be one
 * of: 'error', 'warn', 'info', 'debug', or 'trace'." (CHARIOT-SPEC.md:1553)
 */
export const CHARIOT_LOG_LEVELS: readonly LogLevel[] = ['error', 'warn', 'info', 'debug', 'trace'];

/**
 * CHARIOT::§20::8 — validate CHARIOT_LOG_LEVEL once, at process start
 * (called from engine/bin/setup.ts main(), before any command runs).
 * Throws when the variable is set to a value outside the 5 accepted
 * strings, so a typo fails fast at startup rather than silently falling
 * back to a different level deep inside some component's logger. Unset is
 * valid (defaults to 'info' — see resolveLevel below).
 */
export function validateChariotLogLevel(): void {
  const raw = typeof process !== 'undefined' ? process.env?.CHARIOT_LOG_LEVEL : undefined;
  if (raw === undefined) return;
  if (!(CHARIOT_LOG_LEVELS as readonly string[]).includes(raw)) {
    throw new Error(
      `Chariot startup: CHARIOT_LOG_LEVEL=${JSON.stringify(raw)} is invalid. ` +
      `Must be one of: ${CHARIOT_LOG_LEVELS.join(', ')}.`
    );
  }
}

function resolveLevel(explicit?: LogLevel): LogLevel {
  if (explicit) return explicit;
  const chariotEnv = typeof process !== 'undefined' ? process.env?.CHARIOT_LOG_LEVEL : undefined;
  if (chariotEnv !== undefined) {
    // An invalid value is rejected once, at startup, by
    // validateChariotLogLevel(); fall through to the spec default here
    // rather than throwing on every createLogger() call.
    return (CHARIOT_LOG_LEVELS as readonly string[]).includes(chariotEnv)
      ? (chariotEnv as LogLevel)
      : 'info';
  }
  // Legacy fallback: EPICAI_LOG, only consulted when CHARIOT_LOG_LEVEL is unset.
  const legacyEnv = (typeof process !== 'undefined' && process.env?.EPICAI_LOG) || '';
  if (legacyEnv && legacyEnv in LEVEL_ORDER) return legacyEnv as LogLevel;
  // CHARIOT::§20::8 — default level when CHARIOT_LOG_LEVEL is unset is 'info'.
  return 'info';
}

export interface LoggerInterface {
  debug(message: string, data?: Record<string, unknown>): void;
  info(message: string, data?: Record<string, unknown>): void;
  warn(message: string, data?: Record<string, unknown>): void;
  error(message: string, data?: Record<string, unknown>): void;
  flush(): Promise<void>;
}

// ---------------------------------------------------------------------------
// Loki transport — batched HTTP push, zero dependencies
// ---------------------------------------------------------------------------

interface LokiEntry {
  ts: string;       // nanosecond timestamp
  line: string;     // JSON log line
  level: string;
  component: string;
}

let lokiBuffer: LokiEntry[] = [];
let lokiFlushTimer: ReturnType<typeof setTimeout> | null = null;
const LOKI_FLUSH_INTERVAL_MS = 2000;
const LOKI_MAX_BUFFER = 50;

function lokiEnabled(): boolean {
  return !!(
    typeof process !== 'undefined' &&
    process.env?.EPICAI_LOG_LOKI_URL &&
    process.env?.EPICAI_LOG_LOKI_TOKEN
  );
}

function queueLoki(component: string, level: string, line: string): void {
  if (!lokiEnabled()) return;

  const ts = (Date.now() * 1_000_000).toString(); // nanoseconds
  lokiBuffer.push({ ts, line, level, component });

  if (lokiBuffer.length >= LOKI_MAX_BUFFER) {
    void flushLoki();
  }

  if (!lokiFlushTimer) {
    lokiFlushTimer = setTimeout(() => {
      lokiFlushTimer = null;
      void flushLoki();
    }, LOKI_FLUSH_INTERVAL_MS);
    // Don't keep the process alive just for log flushing
    lokiFlushTimer.unref();
  }
}

async function flushLoki(): Promise<void> {
  // Clear pending timer to avoid double-flush
  if (lokiFlushTimer) {
    clearTimeout(lokiFlushTimer);
    lokiFlushTimer = null;
  }

  if (lokiBuffer.length === 0) return;

  const url = process.env.EPICAI_LOG_LOKI_URL;
  if (!url) throw new Error('invariant: EPICAI_LOG_LOKI_URL is not set');
  const user = process.env.EPICAI_LOG_LOKI_USER || '';
  const token = process.env.EPICAI_LOG_LOKI_TOKEN;
  if (!token) throw new Error('invariant: EPICAI_LOG_LOKI_TOKEN is not set');
  const auth = Buffer.from(`${user}:${token}`).toString('base64');

  const entries = [...lokiBuffer];
  lokiBuffer = [];

  // Group by component+level for efficient push
  const streamMap = new Map<string, { stream: Record<string, string>; values: [string, string][] }>();
  for (const entry of entries) {
    const key = `${entry.component}:${entry.level}`;
    if (!streamMap.has(key)) {
      streamMap.set(key, {
        stream: {
          app: 'epicai-core',
          component: entry.component,
          level: entry.level,
          env: process.env.NODE_ENV || 'test',
        },
        values: [],
      });
    }
    const stream = streamMap.get(key);
    if (!stream) throw new Error(`invariant: stream key ${key} missing from map`);
    stream.values.push([entry.ts, entry.line]);
  }

  const payload = { streams: [...streamMap.values()] };

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Basic ${auth}`,
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(5000),
    });

    if (!response.ok) {
      process.stderr.write(`[epicai.logger] Loki push failed: ${response.status}\n`);
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`[epicai.logger] Loki push error: ${msg}\n`);
  }
}

// Flush on natural exit — async handler re-enters the event loop so Node
// waits for the fetch to complete. Does NOT fire on process.exit() (vitest);
// callers must await logger.flush() in teardown for guaranteed delivery.
if (typeof process !== 'undefined') {
  process.on('beforeExit', () => { void flushLoki(); });
}

// ---------------------------------------------------------------------------
// Logger factory
// ---------------------------------------------------------------------------

/**
 * Create a logger instance scoped to a component.
 *
 * Usage:
 *   const log = createLogger('orchestrator', 'debug');
 *   log.debug('Raw Ollama response', { data: responseBody });
 *
 * Or let it read from EPICAI_LOG env var:
 *   const log = createLogger('orchestrator');
 *   // EPICAI_LOG=debug npm test  ← enables debug output
 *
 * Optional Loki transport (for persistent remote logging):
 *   EPICAI_LOG_LOKI_URL=https://logs-prod-XXX.grafana.net/loki/api/v1/push
 *   EPICAI_LOG_LOKI_USER=YOUR_TENANT_ID
 *   EPICAI_LOG_LOKI_TOKEN=glc_...
 *   EPICAI_LOG=debug npm run test:integration
 *
 * CHARIOT::§3.1::8 file sink (opt-in per component):
 *   const log = createLogger('cli.wizard', undefined, { logFile: true });
 *   // appends to <EPIC_AI_DIR>/logs/cli.wizard.log alongside stderr/Loki.
 */
export interface CreateLoggerOptions {
  /**
   * CHARIOT::§3.1::8 — "The system SHALL write wizard and health-check
   * logs to ~/.epic-ai/logs/ (Chariot-process-owned), with Loki-style
   * emission also available." (CHARIOT-SPEC.md:191). Opt-in per component
   * (rather than a blanket file sink for every `createLogger` caller) so
   * the high-frequency MCP/REST dispatch path — which already logs on
   * every tool call — does not acquire a per-request disk write merely by
   * importing this module. Only the two named surfaces (the setup wizard,
   * `chariot health`) enable it; see src/engine/bin/setup.ts.
   */
  logFile?: boolean;
}

/**
 * Best-effort append of one formatted log line to
 * `<EPIC_AI_DIR>/logs/<component>.log` (CHARIOT::§3.1::8; LOGS_DIR honors
 * EPIC_AI_DIR_OVERRIDE the same way every other ~/.epic-ai path does).
 * Never throws: a read-only home directory, a full disk, or a missing
 * LOGS_DIR must not crash or silence the caller's stderr/Loki output,
 * which has already been written by the time this runs.
 */
function appendToLogFile(component: string, line: string): void {
  try {
    if (!existsSync(LOGS_DIR)) mkdirSync(LOGS_DIR, { recursive: true });
    // Component names are fixed string literals at call sites (e.g.
    // 'cli.wizard'), but sanitize defensively so a future caller can never
    // turn a component name into a path escape out of LOGS_DIR.
    const safeName = component.replace(/[^a-zA-Z0-9._-]/g, '_');
    const file = join(LOGS_DIR, `${safeName}.log`);
    appendFileSync(file, line + '\n', { encoding: 'utf-8', mode: 0o600 });
  } catch (err) {
    process.stderr.write(`[epicai.logger] file sink write failed: ${String(err)}\n`);
  }
}

export function createLogger(component: string, level?: LogLevel, opts?: CreateLoggerOptions): LoggerInterface {
  const minLevel = resolveLevel(level);
  const logFileEnabled = opts?.logFile === true;

  function shouldLog(msgLevel: LogLevel): boolean {
    return LEVEL_ORDER[msgLevel] >= LEVEL_ORDER[minLevel];
  }

  function formatStderr(msgLevel: string, message: string, data?: Record<string, unknown>): string {
    const ts = new Date().toISOString();
    const base = `[${ts}] epicai.${component} ${msgLevel.toUpperCase()}: ${message}`;
    if (data && Object.keys(data).length > 0) {
      return `${base} ${JSON.stringify(data)}`;
    }
    return base;
  }

  function formatLoki(msgLevel: string, message: string, data?: Record<string, unknown>): string {
    return JSON.stringify({
      ts: new Date().toISOString(),
      level: msgLevel,
      component,
      message,
      ...data,
    });
  }

  function emit(msgLevel: LogLevel, message: string, data?: Record<string, unknown>): void {
    if (!shouldLog(msgLevel)) return;
    process.stderr.write(formatStderr(msgLevel, message, data) + '\n');
    queueLoki(component, msgLevel, formatLoki(msgLevel, message, data));
    // CHARIOT::§3.1::8 — file sink is additive to stderr/Loki above, never
    // a replacement; only components that opt in via { logFile: true }
    // pay the disk-write cost.
    if (logFileEnabled) appendToLogFile(component, formatLoki(msgLevel, message, data));
  }

  return {
    debug(message: string, data?: Record<string, unknown>): void {
      emit('debug', message, data);
    },
    info(message: string, data?: Record<string, unknown>): void {
      emit('info', message, data);
    },
    warn(message: string, data?: Record<string, unknown>): void {
      emit('warn', message, data);
    },
    error(message: string, data?: Record<string, unknown>): void {
      emit('error', message, data);
    },
    async flush(): Promise<void> {
      await flushLoki();
    },
  };
}

/**
 * Flush the shared Loki buffer. Call this in test teardown (e.g. vitest afterAll)
 * when running with EPICAI_LOG_LOKI_* env vars, since vitest calls process.exit()
 * and the beforeExit handler won't fire.
 *
 *   afterAll(async () => { await flushAllLogs(); });
 */
export async function flushAllLogs(): Promise<void> {
  await flushLoki();
}
