/**
 * Regression eval for CHARIOT §10.7 route-layer emission ("The auth.brute_force_lockout event
 * SHALL be emitted at the route layer") with CHARIOT §10.7 no-separate-alert-path ("There SHALL be
 * no separate critical-alert path inside the rate-limit service").
 *
 * The defect this catches: "Chariot SHALL emit an auth.brute_force_lockout
 * event at the route layer when a brute-force lockout is triggered."
 * Pre-fix, `'auth.brute_force_lockout'` did not exist in ChariotEventType at
 * all (only the dead, never-emitted `'session.brute_force_detected'` was
 * declared) and there was no process-wide `chariotEmitter` singleton for
 * route handlers to emit onto — this file would fail to COMPILE against the
 * pre-fix emitter.ts (unknown export `chariotEmitter`, invalid event-type
 * literal), and the source-inspection assertion below would fail at runtime
 * because src/iam/routes/oauth.ts had no `chariotEmitter.send(` call site at
 * all.
 *
 * Run (after tsc):
 *   node --test dist/observability/emitter.brute-force-lockout.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { chariotEmitter, type ChariotEvent } from './emitter.js';

test('chariotEmitter singleton accepts and delivers an auth.brute_force_lockout event', () => {
  const received: ChariotEvent[] = [];
  const cb = (event: ChariotEvent): void => {
    received.push(event);
  };
  chariotEmitter.on(cb);
  try {
    chariotEmitter.send('auth.brute_force_lockout', {
      severity: 'warning',
      alertWorthy: true,
      data: { tenantId: 't1', clientId: 'c1' },
      message: 'test lockout',
    });
  } finally {
    chariotEmitter.off(cb);
  }
  assert.equal(received.length, 1);
  assert.equal(received[0]?.type, 'auth.brute_force_lockout');
  assert.equal(received[0]?.alertWorthy, true);
});

test('the per-client lockout branch in oauth.ts (route layer) emits auth.brute_force_lockout, not RateLimiter.ts', () => {
  const here = dirname(fileURLToPath(import.meta.url));
  // dist/observability -> repo root is two levels up from dist/.
  const repoRoot = join(here, '..', '..');
  const oauthSrc = readFileSync(join(repoRoot, 'src', 'iam', 'routes', 'oauth.ts'), 'utf-8');
  assert.match(
    oauthSrc,
    /isClientRateLimited[\s\S]{0,400}chariotEmitter\.send\('auth\.brute_force_lockout'/,
    'oauth.ts must emit auth.brute_force_lockout at the route layer immediately after the ' +
      'per-client lockout bucket (isClientRateLimited) trips',
  );

  const rateLimiterSrc = readFileSync(join(repoRoot, 'src', 'engine', 'resilience', 'RateLimiter.ts'), 'utf-8');
  assert.doesNotMatch(
    rateLimiterSrc,
    /auth\.brute_force_lockout/,
    'the rate-limit SERVICE (RateLimiter.ts) must not emit this event itself — ' +
      'CHARIOT §10.7 no-separate-alert-path forbids a separate critical-alert path inside the rate-limit ' +
      'service and CHARIOT §10.7 route-layer emission requires it be wired at the route layer',
  );
});
