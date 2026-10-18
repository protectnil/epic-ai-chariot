/**
 * CHARIOT::§16.2 (CHARIOT-SPEC.md:1354-1365, rulings item 91(2)/105/114(d))
 * — live dispatch orchestration. Tests `wireAlertDispatch()` with a
 * STUBBED `AlertChannelDispatcher`, a stubbed `AlertQueue`-shaped object,
 * and stubbed admin-contact/connected-channels resolvers — proving the
 * orchestration logic (not real Slack/PagerDuty/SendGrid delivery, not
 * real Mongo) for each channel, the critical fan-out, and (review gate
 * finding (d), thread 01a06d96-0132-71b2-92f4-a87dd7611393) that a
 * skipped channel is never silent.
 *
 * Run (after tsc): node --test dist/observability/alertDispatchWiring.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { wireAlertDispatch, normalizeConnectedChannels } from './alertDispatchWiring.js';
import { AlertQueue } from './alerts.js';
import { chariotEmitter, type ChariotEvent } from './emitter.js';
import type { AlertChannelDispatcher, AdminContact, DispatchOutcome } from './alertChannels.js';

const ADMIN: AdminContact = { email: 'admin@tenant.example', slackUserId: 'U0123456' };

function stubDispatcher(skipped: Set<string> = new Set()): { dispatcher: AlertChannelDispatcher; calls: Array<{ channel: string; type: string }> } {
  const calls: Array<{ channel: string; type: string }> = [];
  return {
    calls,
    dispatcher: {
      async dispatch(channel, event): Promise<DispatchOutcome> {
        calls.push({ channel, type: event.type });
        if (skipped.has(channel)) {
          return { ok: false, skipped: true, reason: `${channel} not configured (test stub)` };
        }
        return { ok: true };
      },
    },
  };
}

function emitAndFlush(event: ChariotEvent): Promise<void> {
  chariotEmitter.emit(event);
  // wireAlertDispatch's callback body is async (fire-and-forget `void
  // (async () => {...})()`); yield a macrotask so it completes before assertions.
  return new Promise((resolve) => setTimeout(resolve, 10));
}

test('§16.2: a non-critical alert with Slack connected dispatches to slack only, never touches the queue', async () => {
  const queue = new AlertQueue();
  const { dispatcher, calls } = stubDispatcher();
  const unsubscribe = wireAlertDispatch(
    queue,
    dispatcher,
    async () => ADMIN,
    async () => normalizeConnectedChannels(['slack', 'sendgrid']),
  );
  try {
    await emitAndFlush({
      type: 'adapter.connected',
      timestamp: new Date(),
      severity: 'warning',
      data: { tenantId: 'tenant-a' },
      alertWorthy: true,
    });
    assert.deepEqual(calls, [{ channel: 'slack', type: 'adapter.connected' }]);
    assert.equal(queue.getPending().length, 0);
  } finally {
    unsubscribe();
  }
});

test('§16.2: an alert with NO connected channels routes to the queue only', async () => {
  const queue = new AlertQueue();
  const { dispatcher, calls } = stubDispatcher();
  const unsubscribe = wireAlertDispatch(
    queue, dispatcher,
    async () => ADMIN,
    async () => normalizeConnectedChannels([]),
  );
  try {
    await emitAndFlush({
      type: 'gateway.circuit_opened',
      timestamp: new Date(),
      severity: 'urgent',
      data: { tenantId: 'tenant-b' },
      alertWorthy: true,
    });
    assert.deepEqual(calls, []);
    assert.equal(queue.getPending().length, 1);
  } finally {
    unsubscribe();
  }
});

test('§16.2: an alert with no tenantId in event.data routes to the queue only (no tenant to resolve channels against)', async () => {
  const queue = new AlertQueue();
  const { dispatcher, calls } = stubDispatcher();
  const unsubscribe = wireAlertDispatch(
    queue, dispatcher,
    async () => ADMIN,
    async () => normalizeConnectedChannels(['slack']),
  );
  try {
    await emitAndFlush({
      type: 'mongo.unreachable',
      timestamp: new Date(),
      severity: 'urgent',
      data: {}, // no tenantId — process-wide operational event
      alertWorthy: true,
    });
    assert.deepEqual(calls, [], 'a tenantless event must never reach the dispatcher, since there is no tenant to resolve channels against');
    assert.equal(queue.getPending().length, 1);
  } finally {
    unsubscribe();
  }
});

test('§16.2: a CRITICAL alert with all three channels connected fans out to slack, email, AND pagerduty, plus the queue', async () => {
  const queue = new AlertQueue();
  const { dispatcher, calls } = stubDispatcher();
  const unsubscribe = wireAlertDispatch(
    queue, dispatcher,
    async () => ADMIN,
    async () => normalizeConnectedChannels(['slack', 'sendgrid', 'pagerduty']),
  );
  try {
    await emitAndFlush({
      type: 'audit.gap_detected',
      timestamp: new Date(),
      severity: 'critical',
      data: { tenantId: 'tenant-c' },
      alertWorthy: true,
    });
    assert.deepEqual(
      calls.map((c) => c.channel).sort(),
      ['email', 'pagerduty', 'slack'],
      'critical severity bypasses first-match-wins and fans out to every connected channel',
    );
    assert.equal(queue.getPending().length, 1, 'the queue is never skipped for a critical alert, even when every channel dispatch also fires');
  } finally {
    unsubscribe();
  }
});

test('§16.2: a non-alert-worthy event is never enqueued or dispatched', async () => {
  const queue = new AlertQueue();
  const { dispatcher, calls } = stubDispatcher();
  const unsubscribe = wireAlertDispatch(
    queue, dispatcher,
    async () => ADMIN,
    async () => normalizeConnectedChannels(['slack']),
  );
  try {
    await emitAndFlush({
      type: 'adapter.connected',
      timestamp: new Date(),
      severity: 'info',
      data: { tenantId: 'tenant-d' },
      alertWorthy: false,
    });
    assert.deepEqual(calls, []);
    assert.equal(queue.getPending().length, 0);
  } finally {
    unsubscribe();
  }
});

test('§16.2: a dispatcher error (thrown, not skipped) on one channel does not prevent the queue enqueue or other channels (critical fan-out is best-effort per channel)', async () => {
  const queue = new AlertQueue();
  const calls: string[] = [];
  const dispatcher: AlertChannelDispatcher = {
    async dispatch(channel): Promise<DispatchOutcome> {
      calls.push(channel);
      if (channel === 'slack') throw new Error('simulated slack API failure');
      return { ok: true };
    },
  };
  const errors: string[] = [];
  const unsubscribe = wireAlertDispatch(
    queue, dispatcher,
    async () => ADMIN,
    async () => normalizeConnectedChannels(['slack', 'sendgrid']),
    (channel) => { errors.push(channel); },
  );
  try {
    await emitAndFlush({
      type: 'auth.brute_force_lockout',
      timestamp: new Date(),
      severity: 'critical',
      data: { tenantId: 'tenant-e' },
      alertWorthy: true,
    });
    assert.ok(calls.includes('slack') && calls.includes('email'), 'both channels must be attempted despite slack failing');
    assert.deepEqual(errors, ['slack']);
    assert.equal(queue.getPending().length, 1, 'the queue enqueue must not be skipped by a channel dispatch failure');
  } finally {
    unsubscribe();
  }
});

// ── review gate finding (d): a skipped channel is never silent ─────────────

test('§16.2 gate finding (d): a non-critical alert whose ONLY resolved channel is skipped (unconfigured) is still queued, carrying skippedChannels', async () => {
  const queue = new AlertQueue();
  // Only email is connected (no slack), and the dispatcher reports it skipped.
  const { dispatcher, calls } = stubDispatcher(new Set(['email']));
  const unsubscribe = wireAlertDispatch(
    queue, dispatcher,
    async () => ADMIN,
    async () => normalizeConnectedChannels(['sendgrid']),
  );
  try {
    await emitAndFlush({
      type: 'adapter.connected',
      timestamp: new Date(),
      severity: 'warning',
      data: { tenantId: 'tenant-f' },
      alertWorthy: true,
    });
    assert.deepEqual(calls, [{ channel: 'email', type: 'adapter.connected' }], 'the dispatcher must still be called (that is how the skip is discovered)');
    const pending = queue.getPending();
    assert.equal(pending.length, 1, 'the alert must be queued even though its only resolved channel turned out unconfigured — it must never silently vanish');
    assert.deepEqual(pending[0].event.data.skippedChannels, ['email']);
  } finally {
    unsubscribe();
  }
});

test('§16.2 gate finding (d): the channel dispatcher IS called (and can dispatch successfully) when its configuration IS present — the stub\'s default ok:true path', async () => {
  const queue = new AlertQueue();
  const { dispatcher, calls } = stubDispatcher(); // nothing skipped
  const unsubscribe = wireAlertDispatch(
    queue, dispatcher,
    async () => ADMIN,
    async () => normalizeConnectedChannels(['sendgrid']),
  );
  try {
    await emitAndFlush({
      type: 'adapter.connected',
      timestamp: new Date(),
      severity: 'warning',
      data: { tenantId: 'tenant-g' },
      alertWorthy: true,
    });
    assert.deepEqual(calls, [{ channel: 'email', type: 'adapter.connected' }]);
    assert.equal(queue.getPending().length, 0, 'a successfully dispatched non-critical alert must NOT also be queued');
  } finally {
    unsubscribe();
  }
});

test('§16.2 gate finding (d): a CRITICAL alert with one channel unconfigured still fans out to the OTHER connected channels, and the queue carries only the skipped one', async () => {
  const queue = new AlertQueue();
  // pagerduty is connected but reports skipped (e.g. no service_id configured); slack and email succeed.
  const { dispatcher, calls } = stubDispatcher(new Set(['pagerduty']));
  const unsubscribe = wireAlertDispatch(
    queue, dispatcher,
    async () => ADMIN,
    async () => normalizeConnectedChannels(['slack', 'sendgrid', 'pagerduty']),
  );
  try {
    await emitAndFlush({
      type: 'audit.gap_detected',
      timestamp: new Date(),
      severity: 'critical',
      data: { tenantId: 'tenant-h' },
      alertWorthy: true,
    });
    assert.deepEqual(
      calls.map((c) => c.channel).sort(),
      ['email', 'pagerduty', 'slack'],
      'every connected channel must still be ATTEMPTED, including the one that turns out unconfigured',
    );
    const pending = queue.getPending();
    assert.equal(pending.length, 1, 'critical always queues regardless, but must not double-enqueue because pagerduty also skipped');
    assert.deepEqual(pending[0].event.data.skippedChannels, ['pagerduty'], 'only the genuinely skipped channel is recorded — slack/email succeeded and are not listed');
  } finally {
    unsubscribe();
  }
});
