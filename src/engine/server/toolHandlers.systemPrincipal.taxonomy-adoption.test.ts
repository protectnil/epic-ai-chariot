/**
 * CHARIOT::§16.2 (rulings item 91(2)/112(a)) — the `alert-dispatch` system
 * principal: `resolveRbacDecision` allows it ONLY for the three
 * alert-dispatch tools (Slack `post_message`, `send_email` on
 * sendgrid/amazon-ses, PagerDuty `create_incident`) and denies everything
 * else, replacing the earlier `localMode: true` bypass this unit's prior
 * report flagged for a ruling.
 *
 * REAL BEHAVIORAL test: `resolveRbacDecision` is a pure, exported function
 * (no I/O) — directly callable.
 *
 * Run (after tsc): node --test dist/engine/server/toolHandlers.systemPrincipal.taxonomy-adoption.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolveRbacDecision } from './toolHandlers.js';
import type { CallContext } from './toolHandlers.js';

const SYSTEM_CTX: CallContext = { systemPrincipal: 'alert-dispatch' };

const ALLOWED_TOOLS: Array<{ adapter: string; tool: string }> = [
  { adapter: 'slack', tool: 'post_message' },
  { adapter: 'sendgrid', tool: 'send_email' },
  { adapter: 'amazon-ses', tool: 'send_email' },
  { adapter: 'pagerduty', tool: 'create_incident' },
];

for (const { adapter, tool } of ALLOWED_TOOLS) {
  test(`§16.2 system principal: alert-dispatch is ALLOWED for ${adapter}:${tool}`, () => {
    const decision = resolveRbacDecision(SYSTEM_CTX, adapter, tool);
    assert.equal(decision.allowed, true);
  });
}

const DENIED_TOOLS: Array<{ adapter: string; tool: string; note: string }> = [
  { adapter: 'slack', tool: 'delete_message', note: 'a DIFFERENT tool on an otherwise-allowed adapter must still be denied' },
  { adapter: 'github', tool: 'create_issue', note: 'a completely unrelated adapter/tool must be denied' },
  { adapter: 'pagerduty', tool: 'acknowledge_incident', note: 'a different PagerDuty tool than the one alert-dispatch actually calls must be denied' },
  { adapter: 'mongodb', tool: 'find', note: 'a data-plane tool must never be reachable under this principal' },
];

for (const { adapter, tool, note } of DENIED_TOOLS) {
  test(`§16.2 system principal: alert-dispatch is DENIED for ${adapter}:${tool} (${note})`, () => {
    const decision = resolveRbacDecision(SYSTEM_CTX, adapter, tool);
    assert.equal(decision.allowed, false);
    if (!decision.allowed) {
      assert.equal(decision.errorPayload.isError, true);
      assert.equal(decision.errorPayload.outcome, 'explicit_failure');
    }
  });
}

test('§16.2 system principal: the gate is exclusive — it does NOT fall through to auth/localMode even when both are ALSO present', () => {
  // A context that carries systemPrincipal AND localMode:true AND a
  // permissive auth grant must still be denied for a non-alert tool —
  // the system-principal branch is checked FIRST and is authoritative,
  // never falling through to the broader localMode/auth bypasses.
  const ctx: CallContext = {
    systemPrincipal: 'alert-dispatch',
    localMode: true,
    auth: { userId: 'u1', allowedOperations: { github: ['create_issue'] } },
  };
  const decision = resolveRbacDecision(ctx, 'github', 'create_issue');
  assert.equal(decision.allowed, false, 'systemPrincipal must be authoritative — localMode:true and a permissive auth grant must not leak through it');
});

test('§16.2 system principal: without systemPrincipal, localMode:true still works exactly as before (no regression to the pre-existing tri-state)', () => {
  const decision = resolveRbacDecision({ localMode: true }, 'anything', 'anything');
  assert.equal(decision.allowed, true);
});

// ── Source inspection: no transport ever derives systemPrincipal from caller-supplied request data ──

test('§16.2 system principal: rest.ts never reads/forwards a systemPrincipal field from request data (only alertDispatchWiring.ts, a trusted internal caller, sets it)', () => {
  const restSrc = readFileSync(fileURLToPath(new URL('./transports/rest.js', import.meta.url)), 'utf8');
  assert.doesNotMatch(restSrc, /systemPrincipal/, 'the REST transport must never read, construct, or forward a systemPrincipal field — an external HTTP caller has no way to set this principal');
});

test('§16.2 system principal: http.ts (the streamable-HTTP/SSE MCP transport) never reads/forwards a systemPrincipal field either', () => {
  const httpSrc = readFileSync(fileURLToPath(new URL('./transports/http.js', import.meta.url)), 'utf8');
  assert.doesNotMatch(httpSrc, /systemPrincipal/, 'the streamable-HTTP transport must never read, construct, or forward a systemPrincipal field');
});

test('§16.2 system principal: only alertDispatchWiring.ts constructs a systemPrincipal: \'alert-dispatch\' CallContext', () => {
  const wiringSrc = readFileSync(fileURLToPath(new URL('../../observability/alertDispatchWiring.js', import.meta.url)), 'utf8');
  const count = (wiringSrc.match(/systemPrincipal:\s*'alert-dispatch'/g) ?? []).length;
  assert.equal(count, 3, 'expected exactly the 3 handleCall call sites (slack/email/pagerduty) to set this principal');
});
