/**
 * Regression eval: a dispatch that breaches `timeoutMs` must actually KILL the
 * sandbox (§7.4 / §19::32), and must never kill anything else.
 *
 * The defect this file exists to catch: both sandboxes cleared the pending entry
 * and rejected the caller's promise on timeout, and stopped there. The child
 * process / worker thread kept running — still holding its descriptors, sockets
 * and memory — with no remaining handle that would ever reap it. Every existing
 * test passed, because every existing test asserted on the rejection, which was
 * always correct. Nothing asserted the thing was dead.
 *
 * The second class of defect here is the one an obvious fix introduces: a timer
 * that dereferences the mutable `this.worker` / `this.child` field can kill a
 * REPLACEMENT sandbox installed by a later start(), and a late `exit` event from
 * a dead sandbox can null out its live successor. Both are covered below.
 *
 * Run (after tsc):
 *   node --test dist/engine/federation/sandbox/sandbox-timeout.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import { WorkerSandbox } from './WorkerSandbox.js';
import { ProcessSandbox } from './ProcessSandbox.js';
import { DEFAULT_SANDBOX_CONFIG } from './types.js';
import { isEnterpriseEnvEnabled } from '../../../license/loader.js';

// ── fixture: an adapter whose callTool never resolves ────────────────────────

function hangingAdapterPath(): string {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-sandbox-test-'));
  const file = join(dir, 'hanging-adapter.mjs');
  writeFileSync(
    file,
    `export default class HangingAdapter {
       constructor() { this.tools = []; }
       async callTool() { await new Promise(() => {}); }
     }`,
  );
  return pathToFileURL(file).href;
}

function cfg(timeoutMs: number) {
  return { ...DEFAULT_SANDBOX_CONFIG, mode: 'worker-thread' as const, timeoutMs };
}

/** The worker field is TS-private; the runtime field is what ships and what a
 *  leaked thread would live on, so it is exactly what this regression observes. */
function liveWorker(sandbox: WorkerSandbox): { threadId: number } | null {
  return (sandbox as unknown as { worker: { threadId: number } | null }).worker;
}

/** Same field, typed for the terminate()/on() calls the race tests need to force. */
function rawWorker(w: { threadId: number }): {
  terminate: () => Promise<number>;
  on: (event: string, cb: () => void) => unknown;
} {
  return w as unknown as {
    terminate: () => Promise<number>;
    on: (event: string, cb: () => void) => unknown;
  };
}

/** ProcessSandbox's child field, for the same reason. */
function liveChild(sandbox: ProcessSandbox): { pid?: number; kill: (s: string) => boolean } | null {
  return (sandbox as unknown as { child: { pid?: number; kill: (s: string) => boolean } | null }).child;
}

// ── the regression this file exists to catch ─────────────────────────────────

test('worker sandbox: a dispatch that breaches timeoutMs terminates the worker', async () => {
  const sandbox = new WorkerSandbox(hangingAdapterPath(), cfg(150), {});
  await sandbox.start();

  const before = liveWorker(sandbox);
  assert.ok(before, 'precondition: a worker must be running before the call');

  await assert.rejects(
    () => sandbox.callTool('anything', {}),
    /timeout after 150ms/,
    'the caller must still see a typed timeout rejection',
  );

  // The kill is what was missing. Give the exit event a turn to land.
  await new Promise((r) => setTimeout(r, 250));

  assert.equal(
    liveWorker(sandbox),
    null,
    'timeout MUST terminate the worker — a rejected promise alone leaves the ' +
      'thread running forever with nothing left to reap it (§7.4: SIGKILL on breach)',
  );

  await sandbox.stop();
});

test('worker sandbox: a stale timeout does not kill a replacement worker', async () => {
  const adapter = hangingAdapterPath();
  const sandbox = new WorkerSandbox(adapter, cfg(150), {});
  await sandbox.start();

  const call = sandbox.callTool('anything', {}).catch(() => 'rejected');

  // Replace the worker while the first call's timer is still armed.
  await sandbox.stop();
  await sandbox.start();
  const replacement = liveWorker(sandbox);
  assert.ok(replacement, 'precondition: a replacement worker must be running');

  // Observe the REPLACEMENT THREAD's own liveness, not the sandbox's bookkeeping
  // field. Asserting on the field would pass even if the stale timer had killed the
  // thread, because the exit handler nulls the field either way — a test that agrees
  // with a broken implementation for the wrong reason.
  let replacementExited = false;
  rawWorker(replacement).on('exit', () => { replacementExited = true; });

  assert.equal(await call, 'rejected', 'the original call still rejects');
  await new Promise((r) => setTimeout(r, 300));

  assert.equal(
    replacementExited,
    false,
    'the first call\'s expired timer must NOT terminate the worker that replaced the ' +
      'one it was sent to — the timeout is bound to a worker identity, not to a field',
  );

  await sandbox.stop();
});

test('worker sandbox: a late exit from a superseded worker does not null its replacement', async () => {
  // Deterministic ordering: start() twice WITHOUT stop() in between, so worker A is
  // still alive with its handlers armed at the moment worker B becomes current. Then
  // kill A explicitly. A's exit handler is therefore guaranteed to run after B was
  // installed — the exact interleaving an unguarded `this.worker = null` gets wrong.
  // (Going through stop() would not prove this: stop() awaits terminate(), so A's exit
  // normally lands BEFORE B exists and an unguarded handler would pass.)
  const sandbox = new WorkerSandbox(hangingAdapterPath(), cfg(5_000), {});
  await sandbox.start();
  const first = liveWorker(sandbox);
  assert.ok(first, 'precondition: worker A running');

  await sandbox.start();
  const second = liveWorker(sandbox);
  assert.ok(second, 'precondition: worker B installed');
  assert.notEqual(second.threadId, first.threadId, 'B must be a distinct worker');

  await rawWorker(first).terminate();
  await new Promise((r) => setTimeout(r, 250));

  const after = liveWorker(sandbox);
  assert.ok(
    after && after.threadId === second.threadId,
    'the superseded worker\'s exit handler must not clear the live replacement — doing ' +
      'so makes every later dispatch fail "Worker not started" against a healthy worker',
  );

  await sandbox.stop();
});

test('worker sandbox: a superseded worker\'s exit does not reject the replacement\'s in-flight requests', async () => {
  const sandbox = new WorkerSandbox(hangingAdapterPath(), cfg(5_000), {});
  await sandbox.start();
  const first = liveWorker(sandbox);
  assert.ok(first);

  await sandbox.start(); // B becomes current; A still alive

  // This request is delivered to B and will hang (the fixture never resolves).
  let settled: string | null = null;
  void sandbox.callTool('anything', {}).then(
    () => { settled = 'resolved'; },
    (e: Error) => { settled = `rejected: ${e.message}`; },
  );
  await new Promise((r) => setTimeout(r, 50));

  await rawWorker(first).terminate();
  await new Promise((r) => setTimeout(r, 250));

  assert.equal(
    settled,
    null,
    'a request in flight on the LIVE worker must survive an unrelated worker\'s exit — ' +
      'a pending map rejected wholesale on any exit fails healthy dispatches',
  );

  await sandbox.stop();
});

// ── ProcessSandbox: the same clause, the other implementation ────────────────

function procCfg(timeoutMs: number) {
  return { ...DEFAULT_SANDBOX_CONFIG, mode: 'process' as const, timeoutMs };
}

test('process sandbox: a dispatch that breaches timeoutMs SIGKILLs the child', async () => {
  const sandbox = new ProcessSandbox(hangingAdapterPath(), procCfg(400), {});
  await sandbox.start();

  const before = liveChild(sandbox);
  assert.ok(before?.pid, 'precondition: a child process must be running');
  const pid = before.pid;

  await assert.rejects(
    () => sandbox.callTool('anything', {}),
    /timeout after 400ms/,
    'the caller must still see a typed timeout rejection',
  );

  await new Promise((r) => setTimeout(r, 400));

  // process.kill(pid, 0) throws ESRCH once the pid is gone. This observes the OS,
  // not our own bookkeeping — the leak this guards against is a live OS process.
  let alive = true;
  try {
    process.kill(pid, 0);
  } catch {
    alive = false;
  }
  assert.equal(
    alive,
    false,
    'timeout MUST SIGKILL the child (§7.4: "SIGKILL on breach") — rejecting the ' +
      'promise alone leaves a live process holding its descriptors with nothing to reap it',
  );

  await sandbox.stop();
});

test('process sandbox: a superseded child\'s exit does not null its replacement', async () => {
  const sandbox = new ProcessSandbox(hangingAdapterPath(), procCfg(5_000), {});
  await sandbox.start();
  const first = liveChild(sandbox);
  assert.ok(first?.pid, 'precondition: child A running');

  await sandbox.start();
  const second = liveChild(sandbox);
  assert.ok(second?.pid, 'precondition: child B installed');
  assert.notEqual(second.pid, first.pid, 'B must be a distinct process');

  first.kill('SIGKILL');
  await new Promise((r) => setTimeout(r, 300));

  const after = liveChild(sandbox);
  assert.ok(
    after && after.pid === second.pid,
    'the superseded child\'s exit handler must not clear the live replacement',
  );

  await sandbox.stop();
});

// ── §18.2: the documented enabling value must actually enable ────────────────

test('isEnterpriseEnvEnabled: the documented CHARIOT_ENTERPRISE=1 enables enterprise mode', () => {
  const saved = process.env.CHARIOT_ENTERPRISE;
  try {
    // Every enabling spelling. '1' is what §18.2 documents and is the case that
    // silently failed open before: an operator following the manual got IAM off.
    for (const v of ['1', 'true', 'TRUE', 'True', ' 1 ', '  true  ']) {
      process.env.CHARIOT_ENTERPRISE = v;
      assert.equal(isEnterpriseEnvEnabled(), true, `${JSON.stringify(v)} must enable`);
    }

    // Every non-enabling value. A security control must not be switched on by
    // anything that merely looks truthy.
    for (const v of ['0', 'false', 'FALSE', '', ' ', 'yes', 'on', '2', 'enterprise', 'null']) {
      process.env.CHARIOT_ENTERPRISE = v;
      assert.equal(isEnterpriseEnvEnabled(), false, `${JSON.stringify(v)} must NOT enable`);
    }

    delete process.env.CHARIOT_ENTERPRISE;
    assert.equal(isEnterpriseEnvEnabled(), false, 'unset must not enable');
  } finally {
    if (saved === undefined) delete process.env.CHARIOT_ENTERPRISE;
    else process.env.CHARIOT_ENTERPRISE = saved;
  }
});
