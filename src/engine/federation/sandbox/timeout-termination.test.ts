/**
 * Prove-on-revert for CHARIOT §7.4::7 (amended 2026-07-25).
 *
 * Amended clause (CHARIOT-SPEC.md §7.4):
 *   "- `timeoutMs` — wall-clock cap per tool dispatch; forcible termination on
 *    breach: `SIGKILL` for process sandboxes and `worker.terminate()` for
 *    worker-thread sandboxes (a `worker_threads` Worker is not an OS process
 *    and cannot receive a signal)."
 *
 * Amended node §7.4::7:
 *   "Each sandbox SHALL enforce timeoutMs as a wall-clock cap per tool dispatch
 *    and SHALL forcibly terminate execution on breach: SIGKILL for process
 *    sandboxes and worker.terminate() for worker-thread sandboxes."
 *
 * Why the clause was amended rather than the code: the previous wording said
 * "SIGKILL on breach" for EVERY sandbox, which is not physically achievable —
 * a worker_threads Worker is not an OS process and cannot receive a signal.
 * WorkerSandbox's terminate() is the correct forcible-termination primitive for
 * that process model, so the clause was corrected to state the truth per
 * sandbox type rather than weakening a shipped control.
 *
 * The defect this guards against is a sandbox that lets a hung dispatch run
 * past timeoutMs with no forcible termination at all.
 *
 * Run (after tsc): node --test dist/engine/federation/sandbox/timeout-termination.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const workerSrc = readFileSync(
  fileURLToPath(new URL('./WorkerSandbox.js', import.meta.url)),
  'utf8',
);
const processSrc = readFileSync(
  fileURLToPath(new URL('./ProcessSandbox.js', import.meta.url)),
  'utf8',
);

test('§7.4::7: the worker sandbox forcibly terminates on the timeoutMs breach', () => {
  // The timeout timer must call terminate() — worker_threads has no signal path.
  assert.ok(
    /setTimeout\(/.test(workerSrc),
    'WorkerSandbox must arm a wall-clock timer for timeoutMs',
  );
  assert.ok(
    /worker\.terminate\(\)/.test(workerSrc),
    'WorkerSandbox must forcibly terminate the worker on breach',
  );
  assert.ok(
    /this\.config\.timeoutMs/.test(workerSrc),
    'the cap must come from the configured timeoutMs, not a literal',
  );
});

test('§7.4::7: the process sandbox issues SIGKILL on the timeoutMs breach', () => {
  assert.ok(
    /kill\('SIGKILL'\)/.test(processSrc),
    'ProcessSandbox must SIGKILL on breach — a child process CAN receive a signal',
  );
  assert.ok(
    /timeoutMs/.test(processSrc),
    'ProcessSandbox must bound dispatch by timeoutMs',
  );
});

test('§7.4::7: the worker sandbox does NOT pretend to deliver a signal', () => {
  // A regression here would be someone "fixing" the old clause literally by
  // calling process.kill on a worker thread id, which does not terminate it.
  assert.ok(
    !/process\.kill\(/.test(workerSrc),
    'a worker thread cannot be terminated with an OS signal; terminate() is the primitive',
  );
});
