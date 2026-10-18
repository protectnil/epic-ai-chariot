/**
 * @epicai/chariot — Process Sandbox
 * Runs vendor/community adapters in a child process with OS-level isolation.
 * No inherited env vars beyond allowlist. No inherited file descriptors.
 * Credentials injected once via startup IPC message.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { spawn, type ChildProcess } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createLogger } from '../../logger.js';
import type { Tool, ToolResult } from '../../types/index.js';
import type { AdapterSandboxConfig } from './types.js';
import { resolveSeccompWrapper, SECCOMP_WRAPPER_PATH } from './seccompWrapper.js';

const log = createLogger('federation.sandbox.process');

interface IPCMessage {
  id: string;
  type: 'init' | 'tools' | 'callTool' | 'result' | 'error';
  adapterPath?: string;
  credentials?: Record<string, string>;
  name?: string;
  args?: Record<string, unknown>;
  result?: ToolResult;
  tools?: Tool[];
  error?: string;
}

export class ProcessSandbox {
  private child: ReturnType<typeof spawn> | null = null;
  /**
   * Each entry records the child it was actually written to. A late `exit` from a
   * replaced child must reject only ITS OWN in-flight requests, never those already
   * dispatched to the live replacement.
   */
  private readonly pending = new Map<
    string,
    { resolve: (v: unknown) => void; reject: (e: Error) => void; child: ChildProcess }
  >();
  private msgId = 0;
  private buffer = '';
  /**
   * Credentials are held only until they have been written to the
   * child process's init message. After `start()`'s `send({ type:
   * 'init', credentials })` returns, the field is overwritten with
   * an empty object so any serialization of this shim cannot leak
   * the secret to chariot's main-process transcript.
 * (Simplify P1 finding on .)
   */
  private credentials: Record<string, string>;
  /**
   * §7.4: "enforce maxMemoryMb as an RSS cap with SIGKILL on breach." The
   * `--max-old-space-size` node arg (see `start()`) only bounds the V8 JS
   * heap — it does not cap resident set size and a breach throws inside the
   * process rather than delivering SIGKILL. This timer polls the child's
   * actual RSS from /proc and SIGKILLs it on breach, independent of V8's
   * own (much narrower) heap accounting.
   */
  private rssMonitorTimer: ReturnType<typeof setInterval> | null = null;
  private static readonly RSS_CHECK_INTERVAL_MS = 1000;

  constructor(
    private readonly adapterPath: string,
    private readonly config: AdapterSandboxConfig,
    credentials: Record<string, string>,
  ) {
    this.credentials = credentials;
  }

  async start(): Promise<void> {
    const nodeArgs = [
      `--max-old-space-size=${this.config.maxMemoryMb}`,
      '--input-type=module',
      '-e',
      this.buildChildScript(),
    ];

    const env = this.buildEnv();

    // GAP #11 — on Linux, run the adapter child under a seccomp-bpf +
    // no_new_privs confinement wrapper instead of spawning node directly.
    // This is the npx/no-pod path's equivalent of the helm chart's pod-level
    // NetworkPolicy/seccomp controls (there is no pod here to apply those
    // to). Non-Linux platforms and Linux builds where the wrapper binary
    // hasn't been compiled both fall back to the prior, unconfined spawn —
    // this is a WARN-and-degrade fallback, never a silent claim of
    // confinement (see seccompWrapper.ts).
    const wrapperPath = resolveSeccompWrapper();
    const command = wrapperPath ?? process.execPath;
    const spawnArgs = wrapperPath ? [process.execPath, ...nodeArgs] : nodeArgs;

    if (wrapperPath) {
      log.info('spawning adapter child under seccomp-bpf confinement', { adapter: this.adapterPath, wrapper: wrapperPath });
    } else if (process.platform === 'linux') {
      log.warn('seccomp confinement wrapper not found; spawning adapter child UNCONFINED', {
        adapter: this.adapterPath,
        expectedPath: SECCOMP_WRAPPER_PATH,
        hint: 'run `npm run build:native` (requires a Rust toolchain) to build native/chariot-seccomp-wrapper',
      });
    }

    this.child = spawn(command, spawnArgs, {
      stdio: ['pipe', 'pipe', 'pipe'],
      env,
    });

    // JSON-RPC over stdout (one JSON object per line)
    if (!this.child.stdout) throw new Error('invariant: child stdout is null');
    this.child.stdout.on('data', (chunk: Buffer) => {
      this.buffer += chunk.toString();
      const lines = this.buffer.split('\n');
      const tail = lines.pop();
      this.buffer = tail ?? ''; // Keep incomplete line in buffer

      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const msg = JSON.parse(line) as IPCMessage;
          const handler = this.pending.get(msg.id);
          if (!handler) continue;
          this.pending.delete(msg.id);

          if (msg.type === 'error') {
            handler.reject(new Error(msg.error ?? 'Process sandbox error'));
          } else {
            handler.resolve(msg);
          }
        } catch {
          log.warn('unparseable message from sandbox', { line: line.slice(0, 200) });
        }
      }
    });

    if (!this.child.stderr) throw new Error('invariant: child stderr is null');
    this.child.stderr.on('data', (chunk: Buffer) => {
      log.debug('sandbox stderr', { adapter: this.adapterPath, output: chunk.toString().slice(0, 500) });
    });

    const child = this.child;
    child.on('exit', (code) => {
      if (code !== 0) {
        log.warn('sandbox process exited', { adapter: this.adapterPath, code });
      }
      // Reject only the requests that belong to THIS child. A stale exit from a
      // replaced generation must not fail requests in flight on its successor.
      for (const [id, handler] of this.pending) {
        if (handler.child !== child) continue;
        this.pending.delete(id);
        handler.reject(new Error(`Sandbox exited with code ${code}`));
      }
      // Identity-guarded: a late exit from a previous child must not null out the
      // replacement that start() has already installed.
      if (this.child === child) this.child = null;
      this.stopRssMonitor();
    });

    this.startRssMonitor(child);

    // Send init message with credentials
    await this.send({
      type: 'init',
      adapterPath: this.adapterPath,
      credentials: this.credentials,
    });
    // Scrub credentials after the child has acknowledged init.
    // The handshake awaits the child's response, so by this point
    // the credentials have crossed the IPC boundary and the
    // chariot-side process no longer needs to retain them.
    this.credentials = {};

    log.info('process sandbox started', { adapter: this.adapterPath, pid: this.child.pid });
  }

  async listTools(): Promise<Tool[]> {
    const response = await this.send({ type: 'tools' }) as IPCMessage;
    return response.tools ?? [];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    const response = await this.send({ type: 'callTool', name, args }) as IPCMessage;
    return response.result ?? { content: [{ type: 'text', text: '' }], isError: true, server: '', tool: name, durationMs: 0 };
  }

  /**
   * Poll the child's actual RSS from /proc/{pid}/status and SIGKILL it the
   * moment it exceeds `config.maxMemoryMb` (§7.4). Linux-only: /proc is not
   * available on other platforms, so the monitor is a no-op there and the
   * V8-heap `--max-old-space-size` bound above remains the only defense —
   * consistent with this module's existing fail-open-with-a-WARN posture
   * for platform-dependent confinement (see `resolveSeccompWrapper`).
   */
  private startRssMonitor(child: ChildProcess): void {
    if (process.platform !== 'linux' || !child.pid) return;
    const pid = child.pid;
    const limitBytes = this.config.maxMemoryMb * 1024 * 1024;
    this.rssMonitorTimer = setInterval(() => {
      if (this.child !== child) {
        this.stopRssMonitor();
        return;
      }
      let status: string;
      try {
        status = readFileSync(`/proc/${pid}/status`, 'utf-8');
      } catch {
        // Process has likely already exited; the exit handler clears the timer.
        return;
      }
      const match = /^VmRSS:\s+(\d+)\s+kB/m.exec(status);
      if (!match) return;
      const rssBytes = Number(match[1]) * 1024;
      if (rssBytes > limitBytes) {
        log.warn('sandbox_rss_limit_breach', {
          adapter: this.adapterPath,
          pid,
          rssBytes,
          limitBytes,
        });
        child.kill('SIGKILL');
      }
    }, ProcessSandbox.RSS_CHECK_INTERVAL_MS);
    if (typeof this.rssMonitorTimer === 'object' && 'unref' in this.rssMonitorTimer) {
      this.rssMonitorTimer.unref();
    }
  }

  private stopRssMonitor(): void {
    if (this.rssMonitorTimer) {
      clearInterval(this.rssMonitorTimer);
      this.rssMonitorTimer = null;
    }
  }

  stop(): Promise<void> {
    this.stopRssMonitor();
    const child = this.child;
    if (child) {
      child.kill('SIGTERM');
      // Force kill after 5s if still running. Bound to the captured child: start()
      // may install a replacement inside that window, and this timer must never
      // SIGKILL a healthy successor.
      const forceKill = setTimeout(() => {
        child.kill('SIGKILL');
      }, 5_000);
      if (typeof forceKill === 'object' && 'unref' in forceKill) {
        forceKill.unref();
      }
    }
    return Promise.resolve();
  }

  private send(msg: Partial<IPCMessage>): Promise<unknown> {
    return new Promise((resolve, reject) => {
      if (!this.child || !this.child.stdin) {
        reject(new Error('Sandbox not started'));
        return;
      }
      // Identity, captured at send time: the timeout below must only ever kill the
      // child this request was actually written to, never a replacement.
      const child = this.child;

      const id = String(++this.msgId);
      const fullMsg = { ...msg, id };

      const timer = setTimeout(() => {
        this.pending.delete(id);
        // §7.4: "wall-clock cap per tool dispatch; SIGKILL on breach." Rejecting the
        // caller's promise alone leaves the child alive, still holding its file
        // descriptors, sockets and memory, with no remaining handle that would ever
        // reap it. The exit handler rejects whatever else was in flight. Skipped when
        // this child has already been replaced — a stale timer must not kill a live one.
        if (this.child === child) {
          child.kill('SIGKILL');
        }
        reject(new Error(`Sandbox timeout after ${this.config.timeoutMs}ms`));
      }, this.config.timeoutMs);

      this.pending.set(id, {
        resolve: (v) => { clearTimeout(timer); resolve(v); },
        reject: (e) => { clearTimeout(timer); reject(e); },
        child,
      });

      this.child.stdin.write(JSON.stringify(fullMsg) + '\n');
    });
  }

  private buildEnv(): Record<string, string> {
    const env: Record<string, string> = {
      NODE_ENV: process.env.NODE_ENV ?? 'production',
      PATH: process.env.PATH ?? '',
    };
    for (const key of this.config.allowedEnvVars) {
      const value = process.env[key];
      if (value !== undefined) {
        env[key] = value;
      }
    }
    return env;
  }

  private buildChildScript(): string {
    return `
      import { stdin, stdout } from 'node:process';
      import { createInterface } from 'node:readline';

      let adapter = null;
      const rl = createInterface({ input: stdin });

      rl.on('line', async (line) => {
        let msg;
        try { msg = JSON.parse(line); } catch { return; }

        try {
          if (msg.type === 'init') {
            const mod = await import(msg.adapterPath);
            const AdapterClass = mod.default ?? Object.values(mod)[0];
            adapter = new AdapterClass(msg.credentials);
            if (adapter.connect) await adapter.connect();
            stdout.write(JSON.stringify({ id: msg.id, type: 'result' }) + '\\n');
          } else if (msg.type === 'tools') {
            const tools = adapter.tools ?? [];
            stdout.write(JSON.stringify({ id: msg.id, type: 'result', tools }) + '\\n');
          } else if (msg.type === 'callTool') {
            const result = await adapter.callTool(msg.name, msg.args);
            stdout.write(JSON.stringify({ id: msg.id, type: 'result', result }) + '\\n');
          }
        } catch (err) {
          stdout.write(JSON.stringify({ id: msg.id, type: 'error', error: err.message }) + '\\n');
        }
      });
    `;
  }
}
