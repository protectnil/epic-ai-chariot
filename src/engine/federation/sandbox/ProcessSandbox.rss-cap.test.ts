/**
 * Regression eval: ProcessSandbox enforces maxMemoryMb as an RSS cap with
 * SIGKILL on breach (§7.4::6), not just a V8 JS-heap limit.
 *
 * The defect this exists to catch: `start()` only ever wired maxMemoryMb to
 * `--max-old-space-size`, a V8 JS-heap limit. `Buffer.alloc()` memory lives
 * OUTSIDE the V8 heap (it backs onto native/external allocations), so a
 * child that allocates and retains large Buffers can blow far past
 * maxMemoryMb in actual resident memory while `--max-old-space-size` never
 * sees anything to object to — the process just keeps running. This test's
 * fixture does exactly that: it allocates buffers well over the configured
 * cap and holds references so they cannot be GC'd, while doing no JS-heap
 * allocation of consequence. Pre-fix, nothing ever kills it. Post-fix, the
 * RSS monitor added by startRssMonitor() polls /proc/{pid}/status and
 * SIGKILLs the child once VmRSS exceeds the limit.
 *
 * Linux-only (the fix reads /proc): skipped elsewhere, matching the fix's
 * own documented platform scope.
 *
 * Run (after tsc):
 *   node --test dist/engine/federation/sandbox/ProcessSandbox.rss-cap.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import { ProcessSandbox } from './ProcessSandbox.js';
import { DEFAULT_SANDBOX_CONFIG } from './types.js';

function memoryHogAdapterPath(): string {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-sandbox-rss-test-'));
  const file = join(dir, 'memory-hog-adapter.mjs');
  writeFileSync(
    file,
    `export default class MemoryHogAdapter {
       constructor() {
         this.tools = [];
         // Off-heap allocation (Buffer backing store is native memory, not
         // V8 old-space) — inflates RSS without tripping --max-old-space-size.
         this._held = [];
         for (let i = 0; i < 8; i++) {
           this._held.push(Buffer.alloc(20 * 1024 * 1024, 1)); // 8 * 20MB = 160MB
         }
       }
       async callTool() { await new Promise(() => {}); }
     }`,
  );
  return pathToFileURL(file).href;
}

function liveChild(sandbox: ProcessSandbox): { pid?: number } | null {
  return (sandbox as unknown as { child: { pid?: number } | null }).child;
}

test(
  'process sandbox: RSS over maxMemoryMb is SIGKILLed even when the JS heap stays small',
  { skip: process.platform !== 'linux' ? 'RSS monitor is Linux-only (/proc)' : false },
  async () => {
    const cfg = { ...DEFAULT_SANDBOX_CONFIG, mode: 'process' as const, maxMemoryMb: 64, timeoutMs: 30_000 };
    const sandbox = new ProcessSandbox(memoryHogAdapterPath(), cfg, {});
    await sandbox.start();

    const before = liveChild(sandbox);
    assert.ok(before?.pid, 'precondition: a child process must be running');
    const pid = before.pid;

    // Give the RSS monitor (1s poll interval) time to observe the breach and kill.
    await new Promise((r) => setTimeout(r, 2_500));

    let alive = true;
    try {
      process.kill(pid, 0);
    } catch {
      alive = false;
    }
    assert.equal(
      alive,
      false,
      '§7.4::6: a child whose RSS exceeds maxMemoryMb MUST be SIGKILLed — a JS-heap-only ' +
        'limit never catches off-heap Buffer growth',
    );

    await sandbox.stop();
  },
);
