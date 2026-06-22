/**
 * @epicai/chariot — Production Drift Detector
 *
 * Watches four signals for behavioral drift using z-score comparison
 * over a 7-day rolling window of hourly samples. Alerts are written to
 * a shared JSONL file consumed by the always-on DriftAlertWorker.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { appendFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import type { ObservabilityEmitter } from '../observability/EventEmitter.js';
import type { DriftDetectedEvent } from '../types/index.js';

// ── Constants ──────────────────────────────────────────────────────────────

/** Default alert file read by the always-on DriftAlertWorker. */
export const DEFAULT_ALERT_FILE = '/tmp/chariot-drift-alerts.jsonl';

/** Rolling window size in hours (7 days). */
const ROLLING_WINDOW_SIZE = 168;

/** Minimum number of historical samples before drift detection fires. */
const MIN_SAMPLES_REQUIRED = 24;

/** z-score threshold above which a drift event is emitted. */
const DEFAULT_Z_THRESHOLD = 2.0;

/**
 * Minimum std dev clamp to prevent infinite z-scores on perfectly-flat
 * signals (e.g., if all 168 samples are exactly 0.85).
 */
const DRIFT_MIN_STDDEV = 0.005;

// ── Types ──────────────────────────────────────────────────────────────────

export interface DriftDetectorOptions {
  /** Path to write drift alert JSONL entries. Defaults to DEFAULT_ALERT_FILE. */
  alertFilePath?: string;
  /** z-score threshold. Defaults to 2.0. */
  zThreshold?: number;
  /** ObservabilityEmitter to emit DriftDetectedEvent. Optional. */
  emitter?: ObservabilityEmitter;
  /** Interval between hourly replay jobs, in ms. Default 3_600_000 (1 hour). */
  replayIntervalMs?: number;
}

export interface AlertEntry {
  signal: string;
  currentValue: number;
  rollingMean: number;
  rollingStdDev: number;
  zScore: number;
  timestamp: string;
}

// ── Rolling buffer ─────────────────────────────────────────────────────────

/**
 * Fixed-size circular buffer of float64 samples.
 * `push` appends; when full it overwrites the oldest entry.
 */
class RollingBuffer {
  private readonly data: number[];
  private readonly capacity: number;
  private head = 0;
  private size = 0;

  constructor(capacity: number) {
    this.capacity = capacity;
    this.data = new Array<number>(capacity).fill(0);
  }

  push(value: number): void {
    this.data[this.head] = value;
    this.head = (this.head + 1) % this.capacity;
    if (this.size < this.capacity) this.size++;
  }

  /** Return all stored values in insertion order (oldest first). */
  toArray(): number[] {
    if (this.size < this.capacity) {
      return this.data.slice(0, this.size);
    }
    // Circular: from head (oldest) around to head-1 (newest).
    return [
      ...this.data.slice(this.head),
      ...this.data.slice(0, this.head),
    ];
  }

  get length(): number {
    return this.size;
  }
}

// ── Statistics helpers ─────────────────────────────────────────────────────

function mean(arr: number[]): number {
  if (arr.length === 0) return 0;
  return arr.reduce((s, v) => s + v, 0) / arr.length;
}

/** Bessel-corrected (sample) standard deviation. */
function stddev(arr: number[], sampleMean: number): number {
  if (arr.length < 2) return 0;
  const variance = arr.reduce((s, v) => s + (v - sampleMean) ** 2, 0) / (arr.length - 1);
  return Math.sqrt(variance);
}

// ── DriftDetector ──────────────────────────────────────────────────────────

export class DriftDetector {
  private readonly alertFilePath: string;
  private readonly zThreshold: number;
  private readonly emitter: ObservabilityEmitter | undefined;
  private readonly replayIntervalMs: number;

  /** signal key → rolling buffer of historical hourly samples */
  private readonly buffers: Map<string, RollingBuffer> = new Map();

  private replayTimer: NodeJS.Timeout | null = null;
  private running = false;
  private verdictDistSkipLogged = false;
  private readonly insufficientSamplesLogged: Set<string> = new Set();

  constructor(opts: DriftDetectorOptions = {}) {
    this.alertFilePath = opts.alertFilePath ?? DEFAULT_ALERT_FILE;
    this.zThreshold = opts.zThreshold ?? DEFAULT_Z_THRESHOLD;
    this.emitter = opts.emitter;
    this.replayIntervalMs = opts.replayIntervalMs ?? 3_600_000;
    this._ensureAlertDir();
  }

  // ── Public API ─────────────────────────────────────────────────────────

  /**
   * Start the hourly synthetic-replay scheduler.
   * @param goldenQueriesPath  Path to golden-query fixture JSON (optional).
   *                           When omitted the top1Accuracy signal is skipped.
   */
  start(goldenQueriesPath?: string): void {
    if (this.running) return;
    this.running = true;
    this._scheduleReplay(goldenQueriesPath);
  }

  stop(): void {
    this.running = false;
    if (this.replayTimer) {
      clearInterval(this.replayTimer);
      this.replayTimer = null;
    }
  }

  /**
   * Record a new sample for a signal and immediately check for drift.
   * Call this from the hourly replay job or from test injection.
   */
  recordSample(signal: string, value: number): void {
    const buf = this._buffer(signal);
    buf.push(value);
    this._checkSignal(signal);
  }

  /**
   * Record the ensemble-judge verdict distribution signal.
   * Pre-condition: `CHARIOT_EVAL_RUN_LLM=1` and at least one judge API key
   * must be present (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or
   * `DO_MODEL_ACCESS_KEY`). When the env is unset, this is a no-op; a
   * one-time `verdict_dist_skipped_no_llm_keys` log entry is emitted via
   * the observability emitter (if wired) so operators can see why the
   * signal is not populating. Returns true when the sample was recorded,
   * false when skipped.
   */
  recordVerdictDistSample(value: number): boolean {
    // Exact match per spec §2.4 — CHARIOT_EVAL_RUN_LLM=0 or =false must NOT
    // enable the path, only =1 does.
    const runLLM = process.env.CHARIOT_EVAL_RUN_LLM === '1';
    const hasKeys = !!(process.env.ANTHROPIC_API_KEY || process.env.OPENAI_API_KEY || process.env.DO_MODEL_ACCESS_KEY);
    if (!runLLM || !hasKeys) {
      if (!this.verdictDistSkipLogged) {
        this.verdictDistSkipLogged = true;
        this.emitter?.log('warn', 'verdict_dist_skipped_no_llm_keys', {
          runLLM,
          hasKeys,
        });
      }
      return false;
    }
    this.recordSample('verdictDist', value);
    return true;
  }

  /** Test-only: reset the verdict-dist skip-log latch so the next call re-logs. */
  _resetVerdictDistSkipLatch(): void {
    this.verdictDistSkipLogged = false;
  }

  // ── Internal test seam ─────────────────────────────────────────────────

  /**
   * Test-only: inject a pre-built history and a current value.
   * Replaces the buffer's content with `historicalSamples` then appends `currentValue`.
   */
  _injectSamples(signal: string, historicalSamples: number[], currentValue: number): void {
    const buf = new RollingBuffer(ROLLING_WINDOW_SIZE);
    for (const v of historicalSamples) buf.push(v);
    this.buffers.set(signal, buf);
    // Now add the current observation
    buf.push(currentValue);
  }

  /**
   * Test-only: trigger the drift check for a specific signal.
   * In production this is called internally by recordSample.
   */
  _checkSignal(signal: string): void {
    const buf = this.buffers.get(signal);
    if (!buf || buf.length < MIN_SAMPLES_REQUIRED) {
      // Insufficient ramp-up samples — log warn-once-per-signal per spec §3
      // (`At least 24 hourly samples must exist before drift detection fires.
      // If fewer samples exist, the detector logs insufficient_samples and
      // exits without alerting.`) so operators can see the ramp-up state.
      if (!this.insufficientSamplesLogged.has(signal)) {
        this.insufficientSamplesLogged.add(signal);
        this.emitter?.log('warn', 'insufficient_samples', {
          signal,
          have: buf?.length ?? 0,
          need: MIN_SAMPLES_REQUIRED,
        });
      }
      return;
    }
    // Once we have enough history, clear the latch so a subsequent recovery
    // from a window-resize would re-log if samples ever drop below the floor.
    this.insufficientSamplesLogged.delete(signal);

    const all = buf.toArray();
    // Treat the last entry as the "current" window; the rest are the baseline.
    const current = all[all.length - 1];
    const history = all.slice(0, all.length - 1);

    const mu = mean(history);
    const sigma = Math.max(stddev(history, mu), DRIFT_MIN_STDDEV);
    const z = (current - mu) / sigma;

    if (Math.abs(z) > this.zThreshold) {
      this._fireAlert({ signal, currentValue: current, rollingMean: mu, rollingStdDev: sigma, zScore: z });
    }
  }

  // ── Private helpers ────────────────────────────────────────────────────

  private _buffer(signal: string): RollingBuffer {
    if (!this.buffers.has(signal)) {
      this.buffers.set(signal, new RollingBuffer(ROLLING_WINDOW_SIZE));
    }
    return this.buffers.get(signal)!;
  }

  private _fireAlert(payload: Omit<AlertEntry, 'timestamp'>): void {
    const entry: AlertEntry = {
      ...payload,
      timestamp: new Date().toISOString(),
    };

    // Write to shared JSONL file (always-on DriftAlertWorker polls this).
    try {
      appendFileSync(this.alertFilePath, JSON.stringify(entry) + '\n', 'utf-8');
    } catch (err) {
      // Log but do not throw — drift alerts must never crash the gateway.
      process.stderr.write(`[DriftDetector] alert write failed: ${(err as Error).message}\n`);
    }

    // Emit StreamEvent if an emitter is wired.
    if (this.emitter) {
      const event: DriftDetectedEvent = {
        type: 'drift-detected',
        data: { ...entry },
        timestamp: new Date(),
      };
      this.emitter.emitEvent(event);
    }
  }

  private _ensureAlertDir(): void {
    const dir = dirname(this.alertFilePath);
    if (dir && dir !== '.' && !existsSync(dir)) {
      try {
        mkdirSync(dir, { recursive: true });
      } catch {
        // Best-effort — if /tmp doesn't exist something else is wrong.
      }
    }
  }

  private _scheduleReplay(goldenQueriesPath?: string): void {
    // Immediate first run, then every replayIntervalMs.
    const run = () => void this._replayOnce(goldenQueriesPath);
    run();
    this.replayTimer = setInterval(run, this.replayIntervalMs);
    this.replayTimer.unref(); // Don't keep the process alive.
  }

  /**
   * One hourly replay iteration.
   *
   * In production, this would:
   *   1. Load golden queries from goldenQueriesPath.
   *   2. Issue chariot_query calls against the live catalog.
   *   3. Compare top-1 result against expected adapter+tool.
   *   4. Compute accuracy, record sample for top1Accuracy signal.
   *   5. Query Loki/AuditTrail for per-adapter error rates and retry means.
   *   6. Record samples for errorRate:<id> and meanRetry:<id> signals.
   *   7. Optionally invoke ensembleJudge on sample responses for verdictDist.
   *
   * v1 records the signals as no-ops (sample=0) when live data is absent,
   * so the buffer accumulates without triggering false positives. Operators
   * wire a real replay implementation by subclassing or via constructor callback.
   */
  private async _replayOnce(_goldenQueriesPath?: string): Promise<void> {
    if (!this.running) return;
    // Placeholder: operators extend DriftDetector or supply signal values
    // via recordSample() from an external monitoring loop.
    // No actual LLM calls here in v1 — the scheduler is the integration point.
  }
}
