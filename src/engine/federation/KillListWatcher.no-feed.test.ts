/**
 * CHARIOT::§7.7 — KillListWatcher, feed-absent behavior.
 *
 * CHARIOT-SPEC.md §7.7 (quoted verbatim, on-disk):
 *   "`src/engine/federation/KillListWatcher.ts` exists in the codebase and
 *   runs as part of the federation startup sequence. It expects to consume
 *   a kill-list feed published by the upstream catalog. **The upstream publisher no longer publishes
 *   that feed**... The current state: the watcher polls and finds the feed
 *   empty, emits a single INFO log per startup, and has no runtime effect."
 *
 * Node CHARIOT::§7.7::1 ("KillListWatcher SHALL run as part of the
 * federation startup sequence and SHALL expect to consume a kill-list feed
 * published by the upstream catalog") is satisfied at the EpicAI.start() call site
 * (src/engine/EpicAI.ts) — the watcher is now constructed and started
 * unconditionally, not only when CHARIOT_KILL_LIST_URL happens to be set.
 * Full EpicAI.start() is an expensive integration surface (LLM provider,
 * federation connect, audit init) with no existing colocated test harness
 * for it in this package, so this file tests KillListWatcher itself — the
 * component whose OWN behavior (§7.7::2, no-op with a single INFO log when
 * no feed URL is configured) is what makes the now-unconditional call site
 * safe. This is Test-derived from the clause's own failure enumeration:
 * value (url present vs. absent), first-run boundary (single call to
 * start(), matching EpicAI.start()'s single-call-per-process-lifetime
 * discipline — `if (this.started) throw` — so "once per startup" reduces
 * to "once per start() call" here).
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { KillListWatcher } from './KillListWatcher.js';
import type { FederationManager } from './FederationManager.js';

// Minimal FederationManager stand-in — KillListWatcher only calls
// serverNames() (to diff against) and unloadAdapter() (to act). Neither is
// exercised in the no-feed path under test, but the constructor requires a
// federation reference (the class doc: "the watcher is purposeless without
// a federation to act on"), so a structurally-typed stub satisfies it.
const fakeFederation = {
  serverNames: () => [] as string[],
  unloadAdapter: async () => {
    throw new Error('unloadAdapter must not be called when no kill-list url is configured');
  },
} as unknown as FederationManager;

function captureStderr(): { lines: string[]; restore: () => void } {
  const lines: string[] = [];
  const original = process.stderr.write.bind(process.stderr);
  process.stderr.write = ((chunk: unknown, ...rest: unknown[]) => {
    lines.push(String(chunk));
    // @ts-expect-error — forwarding a variadic overload through a captured stub
    return original(chunk, ...rest);
  }) as typeof process.stderr.write;
  return {
    lines,
    restore: () => { process.stderr.write = original; },
  };
}

test('CHARIOT::§7.7::2 — start() with no feed URL logs exactly one INFO line and has no runtime effect', async () => {
  const originalFetch = globalThis.fetch;
  let fetchCalls = 0;
  globalThis.fetch = (async (...args: Parameters<typeof fetch>) => {
    fetchCalls++;
    return originalFetch(...args);
  }) as typeof fetch;

  const capture = captureStderr();
  try {
    // No `url` — this is the production-default shape: CHARIOT_KILL_LIST_URL
    // is unset because the upstream publisher no longer publishes the feed (§7.7).
    const watcher = new KillListWatcher({ federation: fakeFederation });
    watcher.start();

    // start() with no url returns synchronously (no pending async poll to
    // await), but give the event loop a turn to prove nothing async fires.
    await new Promise((resolve) => setTimeout(resolve, 0));

    const infoLines = capture.lines.filter((l) => l.includes('kill_list_watcher.disabled_no_url'));
    assert.equal(infoLines.length, 1, 'exactly one INFO log per startup, not zero and not more than one');
    assert.match(infoLines[0], /\binfo\b/i, 'the single log line must be at INFO level');

    assert.equal(fetchCalls, 0, 'no runtime effect: the watcher must never fetch when no feed URL is configured');

    watcher.stop(); // must not throw
  } finally {
    capture.restore();
    globalThis.fetch = originalFetch;
  }
});

test('CHARIOT::§7.7::2 — pollNow() against a URL-less watcher is also a no-op (defense in depth)', async () => {
  const originalFetch = globalThis.fetch;
  let fetchCalls = 0;
  globalThis.fetch = (async (...args: Parameters<typeof fetch>) => {
    fetchCalls++;
    return originalFetch(...args);
  }) as typeof fetch;

  try {
    const watcher = new KillListWatcher({ federation: fakeFederation });
    await watcher.pollNow();
    assert.equal(fetchCalls, 0, 'pollOnce() returns immediately when this.url is unset');
  } finally {
    globalThis.fetch = originalFetch;
  }
});
