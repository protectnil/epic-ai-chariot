/**
 * CHARIOT::§16.2 AlertQueue — live channel dispatch (CHARIOT-SPEC.md:1354-
 * 1365, rulings item 91(2)/105).
 *
 * Ruling (team-lead, rulings item 105): subscribe a channel-dispatching
 * AlertQueue to `chariotEmitter` and deliver through the SAME process-wide
 * dispatch path `toolHandlers.handleCall` uses for `chariot_call`, against
 * `ChariotState.getConfiguredAdapters(tenantId)` — no per-session
 * FederationManager, no separate outbound client (CHARIOT::§1.4
 * zero-outbound). `handleCall` is `src/engine/server/toolHandlers.ts:1493`
 * (`export async function handleCall(callArgs, state, context)`), the
 * exact function every `chariot_call` MCP/REST invocation runs through —
 * literally the same call, not a parallel reimplementation.
 *
 * This module has two layers:
 *   1. `wireAlertDispatch()` — the PURE orchestration loop (channel
 *      resolution via `resolveAlertChannels` from alertChannels.ts,
 *      non-queue channels routed to an injected `AlertChannelDispatcher`,
 *      'queue' routed to the injected `AlertQueue`). Fully unit-testable
 *      with a stubbed dispatcher and a stubbed admin-contact/connected-
 *      channels resolver — no Mongo, no chariot_call, no real adapters.
 *   2. `createFederationAlertDispatcher()` / `createMongoAdminContact
 *      Resolver()` — the REAL production implementations `wireAlertDispatch`
 *      is wired to at boot. See each function's own doc comment for what
 *      it does and, for PagerDuty/email specifically, what it cannot do
 *      without tenant-level configuration that does not exist anywhere in
 *      this codebase today (see the doc comment on
 *      `createFederationAlertDispatcher`).
 */
import { chariotEmitter, type ChariotEvent } from './emitter.js';
import type { AlertQueue } from './alerts.js';
import {
  resolveAlertChannels,
  type AdminContact,
  type ConnectedChannels,
  type AlertChannelDispatcher,
  type DispatchOutcome,
} from './alertChannels.js';
import type { ChariotState } from '../engine/server/ChariotState.js';
import { handleCall } from '../engine/server/toolHandlers.js';
import { getCollection } from '../iam/db.js';
import { getByTenantId } from '../iam/services/tenant.js';
import { DEFAULT_ADMIN_GROUP_NAME } from '../iam/services/session.js';
import type { EnterpriseUserDocument } from '../iam/types.js';
import { createLogger } from '../engine/logger.js';

const log = createLogger('observability.alertDispatch');

/** Resolves the admin contact for a tenant, or null if none can be determined. */
export type AdminContactResolver = (tenantId: string) => Promise<AdminContact | null>;

/** Resolves which channels are currently connected for a tenant. */
export type ConnectedChannelsResolver = (tenantId: string) => Promise<ConnectedChannels>;

/**
 * Wire a live chariotEmitter subscriber that resolves and dispatches every
 * alert-worthy event per CHARIOT-SPEC.md:1358-1365. Returns an unsubscribe
 * function.
 *
 * Events with no `data.tenantId` (every process-wide operational event
 * this unit wired — `redis.unreachable`, `mongo.unreachable`,
 * `gateway.backend_unhealthy`, `gateway.circuit_opened`,
 * `catalog.stale_warning`, `catalog.refresh_completed` — none of these
 * are scoped to a single tenant's admin/channel configuration) route
 * straight to the queue: there is no tenant to resolve an admin contact
 * or connected-channel set against, so §16.2's channel-preference order
 * cannot apply. This is a deliberate, evidence-based scope boundary, not
 * an oversight — see the build report for the full list of event types
 * this affects.
 */
export function wireAlertDispatch(
  queue: AlertQueue,
  dispatcher: AlertChannelDispatcher,
  resolveAdminContact: AdminContactResolver,
  resolveConnectedChannels: ConnectedChannelsResolver,
  onDispatchError?: (channel: 'slack' | 'email' | 'pagerduty', event: ChariotEvent, error: unknown) => void,
): () => void {
  const cb = (event: ChariotEvent): void => {
    if (!event.alertWorthy) return;

    void (async () => {
      const tenantId = typeof event.data.tenantId === 'string' ? event.data.tenantId : undefined;

      if (!tenantId) {
        // No tenant to resolve channels against — conversational queue only.
        queue.enqueue(event);
        return;
      }

      const [admin, connected] = await Promise.all([
        resolveAdminContact(tenantId),
        resolveConnectedChannels(tenantId),
      ]);

      // No resolvable admin contact (e.g. no admin-group user found) —
      // still queue-only, same reasoning as the no-tenantId case: none
      // of steps 1-3 in the channel-resolution order can match without a
      // contact to check email/slackUserId against.
      const channels = resolveAlertChannels(event, admin ?? { email: '' }, connected);

      // CHARIOT::§16.2 (rulings item 91(2)/105/114(d), review gate finding
      // (d), thread 01a06d96-0132-71b2-92f4-a87dd7611393) — "a skipped
      // channel is never silent": collect channels the dispatcher reports
      // as skipped (unconfigured, e.g. no verified sender/service) rather
      // than a genuine transport error, and ALWAYS queue the alert when
      // any channel was skipped — even for a non-critical resolution
      // whose ONLY resolved channel (§16.2 first-match-wins) turned out
      // unconfigured, which would otherwise silently drop the alert
      // (resolveAlertChannels chose that channel believing it viable;
      // only the real dispatcher can know it isn't). The 'queue' entry
      // itself is handled once, after the loop, so a critical fan-out
      // (which already includes 'queue' in `channels`) is never
      // double-enqueued.
      const skippedChannels: Array<'slack' | 'email' | 'pagerduty'> = [];

      for (const channel of channels) {
        if (channel === 'queue') continue;
        try {
          // admin is guaranteed non-null here: resolveAlertChannels only
          // selects slack/email/pagerduty when the corresponding
          // connected+contact condition held, which requires a real
          // AdminContact (the `?? { email: '' }` fallback above can never
          // satisfy any of those three conditions on its own).
          const outcome = await dispatcher.dispatch(channel, event, admin!);
          if (!outcome.ok) skippedChannels.push(channel);
        } catch (err) {
          onDispatchError?.(channel, event, err);
        }
      }

      if (channels.includes('queue') || skippedChannels.length > 0) {
        const queuedEvent: ChariotEvent = skippedChannels.length > 0
          ? { ...event, data: { ...event.data, skippedChannels } }
          : event;
        queue.enqueue(queuedEvent);
      }
    })();
  };

  chariotEmitter.on(cb);
  return () => chariotEmitter.off(cb);
}

// ── Production implementations ──────────────────────────────────────────

const EMAIL_ADAPTER_NAMES = new Set(['sendgrid', 'amazon-ses']);
const SLACK_ADAPTER_NAMES = new Set(['slack']);
const PAGERDUTY_ADAPTER_NAMES = new Set(['pagerduty']);

/**
 * Normalize a tenant's configured adapter ids (from
 * `ChariotState.getConfiguredAdapters(tenantId)`) to the three channel
 * names `alertChannels.ts` operates on. An unrecognized adapter id
 * contributes nothing (channels this module does not know how to
 * dispatch through are never silently treated as "connected").
 */
export function normalizeConnectedChannels(adapterIds: Iterable<string>): ConnectedChannels {
  const channels = new Set<'slack' | 'email' | 'pagerduty'>();
  for (const id of adapterIds) {
    if (SLACK_ADAPTER_NAMES.has(id)) channels.add('slack');
    else if (EMAIL_ADAPTER_NAMES.has(id)) channels.add('email');
    else if (PAGERDUTY_ADAPTER_NAMES.has(id)) channels.add('pagerduty');
  }
  return channels;
}

export function createChariotStateConnectedChannelsResolver(state: ChariotState): ConnectedChannelsResolver {
  return async (tenantId: string) => {
    const adapters = state.getConfiguredAdapters(tenantId);
    return normalizeConnectedChannels(adapters.map((a) => a.id));
  };
}

/**
 * Resolve the tenant's admin contact from `iam_users`: the first active
 * user whose `groups` contains the tenant's admin group (`tenant.settings
 * .adminGroupName ?? DEFAULT_ADMIN_GROUP_NAME` — the SAME default
 * `session.ts`'s own `isAdmin` derivation uses). Returns null when no
 * tenant or no matching admin user is found.
 *
 * Single-admin simplification: CHARIOT-SPEC.md:1358-1361's own wording
 * ("admin has a known Slack user ID", "admin email is known") is
 * singular. A tenant with multiple admin-group users gets the first one
 * found (stable Mongo `_id` ascending order, via the collection's natural
 * findOne behavior) — extending this to multi-admin fan-out is future
 * work, not required by the quoted clause text.
 */
export function createMongoAdminContactResolver(): AdminContactResolver {
  return async (tenantId: string) => {
    const tenant = await getByTenantId(tenantId);
    if (!tenant) return null;
    const adminGroupName = tenant.settings.adminGroupName ?? DEFAULT_ADMIN_GROUP_NAME;
    const col = await getCollection<EnterpriseUserDocument>('iam_users');
    const admin = await col.findOne({ tenantId, active: true, groups: adminGroupName });
    if (!admin) return null;
    return { email: admin.email, slackUserId: admin.slackUserId };
  };
}

/**
 * Production `AlertChannelDispatcher`: dispatches through
 * `toolHandlers.handleCall` — the identical function `chariot_call`
 * (MCP/REST) runs through — against the tenant's configured adapter for
 * each channel.
 *
 * Slack is fully wired: `post_message` needs only `channel` (the admin's
 * `slackUserId`, for a DM) and `text` — no tenant-level configuration
 * beyond what `AdminContact`/`ChariotState` already carry.
 *
 * Email (`send_email`, sendgrid/amazon-ses) and PagerDuty
 * (`create_incident`) each require a field this codebase has NO
 * tenant-level configuration store for: `send_email` needs `from` (a
 * SendGrid/SES-verified sender address — see
 * src/engine/mcp-servers/sendgrid.ts's own `from` field description,
 * "must be a verified sender in SendGrid"); `create_incident` needs
 * `service_id` (the target PagerDuty service — see
 * src/engine/mcp-servers/pagerduty.ts's own field description). Neither
 * value is derivable from `AdminContact`, `ChariotState`, or
 * `AdapterCredentialDocument` (grep-checked: that document has no
 * generic per-adapter config/metadata field — src/iam/types.ts:234-249).
 * Rather than fabricate a value, these two channels read an OPERATOR-
 * SET environment variable (`CHARIOT_ALERT_EMAIL_FROM`,
 * `CHARIOT_ALERT_PAGERDUTY_SERVICE_ID`); when unset, dispatch for that
 * channel is skipped with a warning log rather than sending a malformed
 * call. See the build report for why a per-tenant config field was not
 * added in this unit (out of scope: a new IAM/tenant-settings field is a
 * schema change, not an observability wiring change).
 */
export function createFederationAlertDispatcher(state: ChariotState): AlertChannelDispatcher {
  // CHARIOT::§16.2 (rulings item 91(2)/105/114(d), review gate finding
  // (d), thread 01a06d96-0132-71b2-92f4-a87dd7611393) — "a skipped
  // channel is never silent": every skip WARN-logs naming the missing
  // variable AND counts against ChariotMetrics for that channel, then
  // returns `{ ok: false, skipped: true, reason }` so the caller
  // (wireAlertDispatch) queues the alert instead of dropping it.
  function skip(channel: 'slack' | 'email' | 'pagerduty', reason: string): DispatchOutcome {
    log.warn('alert_dispatch.channel_skipped', { channel, reason });
    state.chariotMetrics?.recordAlertDispatchSkipped(channel);
    return { ok: false, skipped: true, reason };
  }

  return {
    async dispatch(channel, event, admin): Promise<DispatchOutcome> {
      const tenantId = typeof event.data.tenantId === 'string' ? event.data.tenantId : undefined;
      const message = event.message ?? `Chariot alert: ${event.type} (${event.severity})`;

      if (channel === 'slack') {
        if (!admin.slackUserId) {
          // resolveAlertChannels should never select this without one —
          // defensive: still reported as a skip, never a silent no-op.
          return skip('slack', 'admin.slackUserId is unset');
        }
        await handleCall(
          { adapter: 'slack', tool: 'post_message', args: { channel: admin.slackUserId, text: message } },
          state,
          // CHARIOT::§16.2 (rulings item 91(2)/112(a)) — the explicit
          // system principal (CallContext.systemPrincipal, toolHandlers.ts),
          // NOT a `localMode: true` bypass: `resolveRbacDecision` allows
          // this principal ONLY for the exact (adapter, tool) pair being
          // called here — every other tool is denied even under this
          // principal, unlike `localMode` which would trust ANY tool.
          { tenantId, systemPrincipal: 'alert-dispatch' },
        );
        return { ok: true };
      }

      if (channel === 'email') {
        const from = process.env.CHARIOT_ALERT_EMAIL_FROM;
        if (!from) {
          return skip('email', 'CHARIOT_ALERT_EMAIL_FROM is not set — no verified sender configured');
        }
        const adapterId = state.getConfiguredAdapters(tenantId ?? '').find((a) => EMAIL_ADAPTER_NAMES.has(a.id))?.id;
        if (!adapterId) {
          return skip('email', 'no sendgrid/amazon-ses adapter is configured for this tenant');
        }
        await handleCall(
          { adapter: adapterId, tool: 'send_email', args: { to: admin.email, from, subject: `Chariot alert: ${event.type}`, text: message } },
          state,
          // CHARIOT::§16.2 (rulings item 91(2)/112(a)) — the explicit
          // system principal (CallContext.systemPrincipal, toolHandlers.ts),
          // NOT a `localMode: true` bypass: `resolveRbacDecision` allows
          // this principal ONLY for the exact (adapter, tool) pair being
          // called here — every other tool is denied even under this
          // principal, unlike `localMode` which would trust ANY tool.
          { tenantId, systemPrincipal: 'alert-dispatch' },
        );
        return { ok: true };
      }

      // channel === 'pagerduty'
      const serviceId = process.env.CHARIOT_ALERT_PAGERDUTY_SERVICE_ID;
      if (!serviceId) {
        return skip('pagerduty', 'CHARIOT_ALERT_PAGERDUTY_SERVICE_ID is not set — no target service configured');
      }
      await handleCall(
        { adapter: 'pagerduty', tool: 'create_incident', args: { title: `Chariot alert: ${event.type}`, service_id: serviceId, body: message } },
        state,
        // CHARIOT::§16.2 (rulings item 91(2)/112(a)) — the explicit
        // system principal (CallContext.systemPrincipal, toolHandlers.ts),
        // NOT a `localMode: true` bypass: `resolveRbacDecision` allows
        // this principal ONLY for the exact (adapter, tool) pair being
        // called here — every other tool is denied even under this
        // principal, unlike `localMode` which would trust ANY tool.
        { tenantId, systemPrincipal: 'alert-dispatch' },
      );
      return { ok: true };
    },
  };
}
