/**
 * @epicai/chariot — Worker Thread Sandbox
 * Runs protectnil-tier adapters in a worker_threads isolate.
 * Credentials injected once via workerData. No shared memory.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { Worker } from 'node:worker_threads';
import { createLogger } from '../../logger.js';
import type { Tool, ToolResult } from '../../types/index.js';
import type { AdapterSandboxConfig } from './types.js';

const log = createLogger('federation.sandbox.worker');

interface WorkerMessage {
  id: string;
  type: 'tools' | 'callTool' | 'result' | 'error';
  name?: string;
  args?: Record<string, unknown>;
  result?: ToolResult;
  tools?: Tool[];
  error?: string;
}

export class WorkerSandbox {
  private worker: Worker | null = null;
  /**
   * Each entry records the worker it was actually delivered to. Ownership is not
   * decorative: a late `exit` from a replaced worker must reject only ITS OWN
   * in-flight requests. Rejecting the whole map would fail requests already
   * dispatched to the live replacement.
   */
  private readonly pending = new Map<
    string,
    { resolve: (v: unknown) => void; reject: (e: Error) => void; worker: Worker }
  >();
  private msgId = 0;
  /**
   * Credentials are held only long enough to hand to the Worker
   * constructor's `workerData`. After `start()` the field is
   * overwritten with an empty object so any serialization of this
   * shim (logs, structured-clone debugger, JSON inspector) cannot
   * leak the secret to chariot's main-process transcript.
 * (Simplify P1 finding on .)
   */
  private credentials: Record<string, string>;

  constructor(
    private readonly adapterPath: string,
    private readonly config: AdapterSandboxConfig,
    credentials: Record<string, string>,
  ) {
    this.credentials = credentials;
  }

  start(): Promise<void> {
    const workerCode = `
      (async () => {
        const { workerData, parentPort } = await import('node:worker_threads');
        const { adapterPath, credentials } = workerData;
        const mod = await import(adapterPath);
        const AdapterClass = mod.default ?? Object.values(mod)[0];
        const adapter = new AdapterClass(credentials);
        if (adapter.connect) await adapter.connect();

        parentPort.on('message', async (msg) => {
          try {
            if (msg.type === 'tools') {
              parentPort.postMessage({ id: msg.id, type: 'result', tools: adapter.tools });
            } else if (msg.type === 'callTool') {
              const result = await adapter.callTool(msg.name, msg.args);
              parentPort.postMessage({ id: msg.id, type: 'result', result });
            }
          } catch (err) {
            parentPort.postMessage({ id: msg.id, type: 'error', error: err.message });
          }
        });
      })().catch((err) => { throw err; });
    `;

    const credsForWorker = this.credentials;
    // Scrub before the Worker is started — Worker creation is sync
    // from the caller's perspective (the worker thread receives a
    // structured-clone of workerData before this line returns).
    this.credentials = {};

    // Every handler below is bound to THIS worker instance, not to the mutable
    // `this.worker` field. A worker that exits late must not act on its
    // replacement: `start()` may already have installed a new one.
    const worker = new Worker(workerCode, {
      eval: true,
      workerData: {
        adapterPath: this.adapterPath,
        credentials: credsForWorker,
      },
      env: this.buildEnv(),
      resourceLimits: {
        maxOldGenerationSizeMb: this.config.maxMemoryMb,
      },
    });
    this.worker = worker;

    worker.on('message', (msg: WorkerMessage) => {
      const handler = this.pending.get(msg.id);
      if (!handler) return;
      this.pending.delete(msg.id);

      if (msg.type === 'error') {
        handler.reject(new Error(msg.error ?? 'Worker error'));
      } else {
        handler.resolve(msg);
      }
    });

    worker.on('error', (err: Error) => {
      log.error('worker error', {
        adapter: this.adapterPath,
        error: err.message,
        errorStack: err.stack,
      });
    });

    worker.on('exit', (code) => {
      if (code !== 0) {
        log.warn('worker exited', { adapter: this.adapterPath, code });
      }
      // Reject only the requests that belong to THIS worker. A stale exit from a
      // replaced generation must not fail requests already in flight on its successor.
      for (const [id, handler] of this.pending) {
        if (handler.worker !== worker) continue;
        this.pending.delete(id);
        handler.reject(new Error(`Worker exited with code ${code}`));
      }
      // A terminated worker must not stay addressable: postMessage() on it silently
      // does nothing, so a later send() would hang until its own timeout instead of
      // failing fast. Guarded on identity — a late exit from a previous worker must
      // not null out the replacement that start() has already installed.
      if (this.worker === worker) this.worker = null;
    });

    log.info('worker sandbox started', { adapter: this.adapterPath });
    return Promise.resolve();
  }

  async listTools(): Promise<Tool[]> {
    const response = await this.send({ type: 'tools' }) as WorkerMessage;
    return response.tools ?? [];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    const response = await this.send({ type: 'callTool', name, args }) as WorkerMessage;
    return response.result ?? { content: [{ type: 'text', text: '' }], isError: true, server: '', tool: name, durationMs: 0 };
  }

  async stop(): Promise<void> {
    const worker = this.worker;
    if (!worker) return;
    await worker.terminate();
    // Identity-guarded: start() may have installed a replacement while the await
    // above was outstanding. An unconditional null here orphans that live worker
    // and every later dispatch fails "Worker not started" against a healthy thread.
    if (this.worker === worker) this.worker = null;
  }

  private send(msg: Partial<WorkerMessage>): Promise<unknown> {
    return new Promise((resolve, reject) => {
      if (!this.worker) {
        reject(new Error('Worker not started'));
        return;
      }
      // Identity, captured at send time: the timeout below must only ever terminate
      // the worker this request was actually delivered to.
      const worker = this.worker;

      const id = String(++this.msgId);
      const fullMsg = { ...msg, id };

      const timer = setTimeout(() => {
        this.pending.delete(id);
        // §7.4: "wall-clock cap per tool dispatch; SIGKILL on breach." terminate() is
        // the worker-thread equivalent; without it the thread keeps running its loop
        // after the caller has already given up on it. Skipped when this worker has
        // already been replaced — otherwise a stale timer kills a live replacement.
        if (this.worker === worker) {
          // try/catch as well as .catch(): terminate() can throw synchronously on an
          // already-destroyed worker, and a throw from a timer callback is an uncaught
          // exception that takes the host process down — the opposite of confinement.
          try {
            worker.terminate().catch((err: unknown) => {
              log.debug('worker terminate after timeout rejected', {
                adapter: this.adapterPath,
                error: err instanceof Error ? err.message : String(err),
              });
            });
          } catch (err: unknown) {
            log.debug('worker terminate after timeout threw', {
              adapter: this.adapterPath,
              error: err instanceof Error ? err.message : String(err),
            });
          }
        }
        reject(new Error(`Worker timeout after ${this.config.timeoutMs}ms`));
      }, this.config.timeoutMs);

      this.pending.set(id, {
        resolve: (v) => { clearTimeout(timer); resolve(v); },
        reject: (e) => { clearTimeout(timer); reject(e); },
        worker,
      });

      worker.postMessage(fullMsg);
    });
  }

  private buildEnv(): Record<string, string> {
    const env: Record<string, string> = {};
    for (const key of this.config.allowedEnvVars) {
      const value = process.env[key];
      if (value !== undefined) {
        env[key] = value;
      }
    }
    return env;
  }
}
