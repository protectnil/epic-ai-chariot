/**
 * CHARIOT::§16.2 AlertQueue channel resolution (CHARIOT-SPEC.md:1358-1365,
 * rulings item 91(2)) — see src/observability/alertChannels.ts header
 * comment for the quoted governing bytes.
 *
 * Full 16-cell truth table: {slack connected, email connected, pagerduty
 * connected, critical} each boolean, 2^4 = 16 combinations, admin always
 * has BOTH email and slackUserId set (so "connected" is the only variable
 * under test in the 16-cell table — the admin-contact-missing cases are
 * covered separately below).
 *
 * Run (after tsc): node --test dist/observability/alertChannels.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  resolveAlertChannels,
  isCriticalAlert,
  CRITICAL_ALERT_EVENT_TYPES,
  type ConnectedChannels,
  type AlertChannel,
} from './alertChannels.js';

const ADMIN = { email: 'admin@tenant.example', slackUserId: 'U0123456' };
const NON_CRITICAL_EVENT = { type: 'adapter.connected' as const, severity: 'info' as const };
const CRITICAL_EVENT = { type: 'audit.gap_detected' as const, severity: 'critical' as const };

function connected(slack: boolean, email: boolean, pagerduty: boolean): ConnectedChannels {
  const s = new Set<'slack' | 'email' | 'pagerduty'>();
  if (slack) s.add('slack');
  if (email) s.add('email');
  if (pagerduty) s.add('pagerduty');
  return s;
}

// The 16-cell table. Expected values derived directly from the quoted
// clause (first-match order 1/2/3/4 for non-critical; "all available plus
// queue" for critical), NOT from the implementation.
const CASES: Array<{ slack: boolean; email: boolean; pagerduty: boolean; critical: boolean; expected: AlertChannel[] }> = [
  // --- non-critical (spec steps 1/2/4 — PagerDuty never reachable here) ---
  { slack: false, email: false, pagerduty: false, critical: false, expected: ['queue'] },
  { slack: false, email: false, pagerduty: true, critical: false, expected: ['queue'] },
  { slack: false, email: true, pagerduty: false, critical: false, expected: ['email'] },
  { slack: false, email: true, pagerduty: true, critical: false, expected: ['email'] },
  { slack: true, email: false, pagerduty: false, critical: false, expected: ['slack'] },
  { slack: true, email: false, pagerduty: true, critical: false, expected: ['slack'] },
  { slack: true, email: true, pagerduty: false, critical: false, expected: ['slack'] },
  { slack: true, email: true, pagerduty: true, critical: false, expected: ['slack'] },
  // --- critical (bypass: every connected channel, ordered, + queue always) ---
  { slack: false, email: false, pagerduty: false, critical: true, expected: ['queue'] },
  { slack: false, email: false, pagerduty: true, critical: true, expected: ['pagerduty', 'queue'] },
  { slack: false, email: true, pagerduty: false, critical: true, expected: ['email', 'queue'] },
  { slack: false, email: true, pagerduty: true, critical: true, expected: ['email', 'pagerduty', 'queue'] },
  { slack: true, email: false, pagerduty: false, critical: true, expected: ['slack', 'queue'] },
  { slack: true, email: false, pagerduty: true, critical: true, expected: ['slack', 'pagerduty', 'queue'] },
  { slack: true, email: true, pagerduty: false, critical: true, expected: ['slack', 'email', 'queue'] },
  { slack: true, email: true, pagerduty: true, critical: true, expected: ['slack', 'email', 'pagerduty', 'queue'] },
];

for (const c of CASES) {
  const label = `slack=${c.slack} email=${c.email} pagerduty=${c.pagerduty} critical=${c.critical}`;
  test(`§16.2 truth table: ${label}`, () => {
    const event = c.critical ? CRITICAL_EVENT : NON_CRITICAL_EVENT;
    const result = resolveAlertChannels(event, ADMIN, connected(c.slack, c.email, c.pagerduty));
    assert.deepEqual(result, c.expected, `for ${label}, expected ${JSON.stringify(c.expected)}, got ${JSON.stringify(result)}`);
  });
}

test('§16.2: critical bypass fires for all three byte-pinned event types regardless of severity field', () => {
  for (const type of CRITICAL_ALERT_EVENT_TYPES) {
    assert.equal(isCriticalAlert({ type, severity: 'info' }), true, `${type} must be treated as critical even if severity is mislabeled 'info'`);
  }
});

test('§16.2: a non-pinned event type with severity "critical" is ALSO treated as critical (general severity trigger)', () => {
  assert.equal(isCriticalAlert({ type: 'gateway.circuit_opened', severity: 'critical' }), true);
});

test('§16.2: an ordinary event (not pinned, not severity critical) is not critical', () => {
  assert.equal(isCriticalAlert({ type: 'adapter.connected', severity: 'warning' }), false);
});

test('§16.2 step 1: Slack adapter connected but admin.slackUserId is undefined does NOT match — falls through to step 2', () => {
  const admin = { email: 'admin@tenant.example' }; // no slackUserId
  const result = resolveAlertChannels(NON_CRITICAL_EVENT, admin, connected(true, true, false));
  assert.deepEqual(result, ['email'], 'admin has no known Slack user ID, so step 1 must not match even though the Slack adapter is connected');
});

test('§16.2 step 1: Slack adapter connected, admin.slackUserId is empty string, does NOT match', () => {
  const admin = { email: 'admin@tenant.example', slackUserId: '' };
  const result = resolveAlertChannels(NON_CRITICAL_EVENT, admin, connected(true, false, false));
  assert.deepEqual(result, ['queue'], 'empty-string slackUserId must not satisfy "admin has a known Slack user ID"');
});

test('§16.2 step 4: no connected adapters at all -> conversational queue, non-critical', () => {
  const result = resolveAlertChannels(NON_CRITICAL_EVENT, ADMIN, connected(false, false, false));
  assert.deepEqual(result, ['queue']);
});

test('§16.2 critical bypass: zero connected adapters -> queue only (nothing else available to add)', () => {
  const result = resolveAlertChannels(CRITICAL_EVENT, ADMIN, connected(false, false, false));
  assert.deepEqual(result, ['queue']);
});

test('§16.2 critical bypass: the queue is ALWAYS appended even when every channel is also connected', () => {
  const result = resolveAlertChannels(CRITICAL_EVENT, ADMIN, connected(true, true, true));
  assert.ok(result.includes('queue'), 'queue must never be skipped for a critical alert');
  assert.equal(result[result.length - 1], 'queue', 'queue is appended last, after every dispatched channel');
});
