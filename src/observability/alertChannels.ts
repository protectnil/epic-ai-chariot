/**
 * CHARIOT::§16.2 AlertQueue channel resolution (CHARIOT-SPEC.md:1354-1365,
 * rulings item 91(2)).
 *
 * Quoted governing bytes (CHARIOT-SPEC.md:1358-1365):
 *   "Channel resolution per alert (in this order, first match wins):
 *    1. Slack adapter connected and admin has a known Slack user ID -> Slack DM.
 *    2. Email adapter connected and admin email is known -> Email.
 *    3. PagerDuty adapter connected and the alert is `Critical` severity -> PagerDuty incident.
 *    4. Conversational queue: surfaced at the start of the admin's next AI conversation.
 *    Critical-severity alerts (`audit.gap_detected`, `auth.brute_force_lockout`,
 *    `catalog.signature_failed`) bypass the channel-preference order and notify
 *    on **all** available channels simultaneously."
 *
 * Ruling (team-lead, rulings item 91(2)): alert channels ARE the tenant's
 * connected catalog adapters (Slack / Email / PagerDuty), dispatched through
 * FederationManager — no first-party outbound integration (CHARIOT::§1.4
 * zero-outbound). Admin contact = the IAM user's email (EnterpriseUserDocument
 * .email, always present) plus the new optional `slackUserId` field
 * (src/iam/types.ts). No connected adapter -> conversational queue. Critical
 * severity -> every connected channel PLUS the queue (the queue is never
 * skipped for critical, since a channel dispatch can itself fail silently —
 * the queue is the one channel that cannot drop the alert).
 *
 * This module is the PURE decision logic only (no I/O, no FederationManager
 * import) so it is exhaustively unit-testable via a truth table. Actual
 * dispatch (sending through a tenant's connected adapter) is a separate,
 * injectable concern — see the `AlertDispatcher` interface below, which a
 * caller wires to FederationManager.callTool(...). See this unit's build
 * report for why that live wiring is not closed in this change.
 */
import type { ChariotEvent, ChariotEventType } from './emitter.js';

export type AlertChannel = 'slack' | 'email' | 'pagerduty' | 'queue';

/**
 * The three CHARIOT-SPEC.md:1365 named critical events. Byte-exact match to
 * the quoted parenthetical above — not a superset, not a guess.
 */
export const CRITICAL_ALERT_EVENT_TYPES: ReadonlySet<ChariotEventType> = new Set<ChariotEventType>([
  'audit.gap_detected',
  'auth.brute_force_lockout',
  'catalog.signature_failed',
]);

/**
 * The admin contact record channel resolution reads. Deliberately narrower
 * than the full EnterpriseUserDocument — this module must not depend on
 * src/iam/types.ts's Mongo-shaped document type.
 */
export interface AdminContact {
  /** EnterpriseUserDocument.email — always present (required field). */
  email: string;
  /** EnterpriseUserDocument.slackUserId — optional; absent = unknown. */
  slackUserId?: string;
}

/**
 * The tenant's connected catalog adapters, by normalized channel name.
 * A caller derives this from ChariotState.getConfiguredAdapters(tenantId)
 * (src/engine/server/ChariotState.ts:534) — normalizing concrete adapter
 * names (e.g. "sendgrid", "amazon-ses") to the "email" channel, and "slack"
 * / "pagerduty" adapter names to their own channel. Normalization is the
 * caller's responsibility (adapter-name catalog is out of this pure
 * module's scope) so this module never hardcodes a vendor adapter name.
 */
export type ConnectedChannels = ReadonlySet<'slack' | 'email' | 'pagerduty'>;

/**
 * §16.1 defines `severity` as `AlertSeverity` ('info'|'warning'|'urgent'|
 * 'critical'). This clause's "Critical-severity alerts" trigger is: EITHER
 * the event's own severity field is literally 'critical', OR the event's
 * type is one of the three byte-pinned names above (defensive: a future
 * emit site could mislabel severity on one of the three named types, and
 * the clause names the types explicitly as its own definition of
 * "critical-severity", independent of the severity field's actual value).
 */
export function isCriticalAlert(event: Pick<ChariotEvent, 'type' | 'severity'>): boolean {
  return event.severity === 'critical' || CRITICAL_ALERT_EVENT_TYPES.has(event.type);
}

/**
 * Resolve the channel(s) a given alert-worthy event should notify, per
 * CHARIOT-SPEC.md:1358-1365 (quoted in the header comment above).
 *
 * Failure classes enumerated and closed:
 *  - No connected adapters at all -> ['queue'] (step 4 fallback).
 *  - Slack adapter connected but admin.slackUserId is undefined/empty ->
 *    step 1 does NOT match (falls through) — "admin has a known Slack user
 *    ID" requires the id, not merely the adapter.
 *  - Email adapter connected but admin.email is empty string -> step 2
 *    does NOT match (defensive; EnterpriseUserDocument.email is a required
 *    field in practice, but this function does not assume that of its
 *    caller).
 *  - PagerDuty connected + non-critical alert -> PagerDuty is NEVER chosen
 *    (spec step 3 itself gates PagerDuty on Critical severity; a non-
 *    critical alert with only PagerDuty connected falls through to queue,
 *    not PagerDuty — this is a spec-mandated non-obvious boundary, not an
 *    oversight).
 *  - Critical alert with ZERO connected adapters -> ['queue'] only (the
 *    "all available channels" bypass has nothing available to add).
 *  - Critical alert with SOME connected adapters -> every one of them,
 *    ORDERED slack, email, pagerduty (deterministic dispatch order for a
 *    caller that must send them one at a time), PLUS 'queue' always
 *    appended last (never skipped for critical).
 *  - Non-critical alert with Slack AND Email both connected -> Slack wins
 *    (first-match-wins order 1 beats 2; Email is never additionally sent).
 */
export function resolveAlertChannels(
  event: Pick<ChariotEvent, 'type' | 'severity'>,
  admin: AdminContact,
  connectedChannels: ConnectedChannels,
): AlertChannel[] {
  const hasSlack = connectedChannels.has('slack') && !!admin.slackUserId;
  const hasEmail = connectedChannels.has('email') && !!admin.email;
  const hasPagerDuty = connectedChannels.has('pagerduty');

  if (isCriticalAlert(event)) {
    const channels: AlertChannel[] = [];
    if (hasSlack) channels.push('slack');
    if (hasEmail) channels.push('email');
    if (hasPagerDuty) channels.push('pagerduty');
    channels.push('queue');
    return channels;
  }

  if (hasSlack) return ['slack'];
  if (hasEmail) return ['email'];
  return ['queue'];
}

/**
 * Result of one `AlertChannelDispatcher.dispatch()` call.
 *
 * CHARIOT::§16.2 (rulings item 91(2)/105/114(d), review gate finding (d),
 * thread 01a06d96-0132-71b2-92f4-a87dd7611393) — "a skipped channel is
 * never silent": a channel that CANNOT be dispatched (e.g. no verified
 * sender/service configured for email/PagerDuty) reports `{ ok: false,
 * skipped: true, reason }` rather than silently returning — the caller
 * (`wireAlertDispatch` in alertDispatchWiring.ts) is responsible for
 * queuing the alert anyway and recording the skip, so the admin still
 * receives it via the §16.2 step-4 conversational queue.
 */
export type DispatchOutcome = { ok: true } | { ok: false; skipped: true; reason: string };

/**
 * Injectable dispatch surface a caller implements against FederationManager
 * .callTool(name, args, tenantId, actor) (src/engine/federation/
 * FederationManager.ts:982) for the non-queue channels. `queue` is never
 * passed here — the caller enqueues into AlertQueue directly instead.
 * Kept as a separate interface (rather than importing FederationManager
 * into this module) so this pure-logic file has zero I/O dependencies.
 */
export interface AlertChannelDispatcher {
  dispatch(channel: 'slack' | 'email' | 'pagerduty', event: ChariotEvent, admin: AdminContact): Promise<DispatchOutcome>;
}
