/**
 * Chariot Event Emitter
 *
 * Structured event system for Chariot-specific telemetry.
 * Events flow to: the AI (via MCP tools), the alert queue,
 * the metrics aggregator, and optionally to external systems.
 */
import { createLogger } from '../engine/logger.js';

// Production logging goes through the project logger (never console.*).
const moduleLog = createLogger('observability.emitter');

export type AlertSeverity = 'info' | 'warning' | 'urgent' | 'critical';

// CHARIOT::§16.1 (rulings item 91, taxonomy option (a)) — every event name
// CHARIOT-SPEC.md:1341-1348 pins is a member of this union, emitted at its
// own natural site (enumerated in the doc comment above each `.send(...)`
// call this ruling added). An existing event with NO spec counterpart
// (not a byte-exact string match to one of the 40 pinned names) is
// RETAINED as-is — it is still real, still consumed by metrics.ts/
// alerts.ts, and removing it would be a silent behavior change this
// ruling does not authorize. The ONE renamed group is `discovery.*`
// (underscore forms → the spec's dotted forms), per explicit ruling.
export type ChariotEventType =
  // ── §16.1 License (CHARIOT-SPEC.md:1345) — all 6 newly wired at their
  // natural site in src/license/loader.ts (validateLicense, cache-miss
  // branch only — never on a cache hit) and src/license/renew-client.ts
  // (renewNow). ──────────────────────────────────────────────────────────
  | 'license.loaded'
  | 'license.expired'
  | 'license.grace_entered'
  | 'license.degraded'
  | 'license.renewed'
  | 'license.renew_failed'
  // Pre-existing license events with no spec-§16.1 counterpart — retained.
  | 'license.checked'
  | 'license.state_changed'
  | 'license.renewal_attempted'
  | 'license.renewal_succeeded'
  | 'license.renewal_failed'
  // ── §16.1 IAM (CHARIOT-SPEC.md:1346) ──────────────────────────────────
  // `mfa.enrolled` wired at src/iam/services/mfa.ts (saveMfaSecret).
  | 'mfa.enrolled'
  // `auth.success` / `auth.failure` / `mfa.skipped_via_idp` /
  // `scim.group_synced`: no natural emit site closed this unit — see the
  // build report's "could not close" section for each's specific blocker.
  // Declared here (type-level adoption) so downstream consumers
  // (alerts.ts critical-bypass list, metrics.ts) and future wiring can
  // reference the exact spec-pinned literal without a second rename later.
  | 'auth.success'
  | 'auth.failure'
  | 'mfa.skipped_via_idp'
  | 'scim.group_synced'
  // `scim.user_provisioned` / `scim.user_deprovisioned` were ALREADY
  // exact spec-string matches before this change — no rename needed,
  // listed with the other SCIM members below.
  | 'scim.user_provisioned'
  | 'scim.user_deprovisioned'
  // Pre-existing IAM/session/RBAC/vault/SCIM events with no spec-§16.1
  // counterpart — retained.
  | 'session.created'
  | 'session.revoked'
  | 'session.expired'
  | 'session.auth_failed'
  | 'session.brute_force_detected'
  // Route-layer auth defenses (CHARIOT §19::22) — emitted by the OAuth/ID-JAG
  // routes themselves (not RateLimiter.ts) when a brute-force lockout bucket
  // trips, so the event carries route context (tenantId/clientId) the
  // rate-limit service does not have. Also an EXACT §16.1 IAM-group match
  // (CHARIOT-SPEC.md:1346) — no rename needed.
  | 'auth.brute_force_lockout'
  | 'rbac.access_granted'
  | 'rbac.access_denied'
  | 'rbac.mapping_changed'
  | 'vault.credential_connected'
  | 'vault.credential_revoked'
  | 'vault.credential_expiring'
  | 'vault.encrypt'
  | 'vault.decrypt'
  // CHARIOT §10.5::2 (rulings item 88(2)) — emitted by the per-user OAuth
  // vendor-token refresh job (src/iam/services/credentials.ts) on a
  // vendor-revoked refresh failure, alongside the existing status:'expired'
  // write. Distinct from `vault.credential_expiring` (a separate,
  // pre-existing pre-expiry warning with no wiring in this unit).
  | 'credential.refresh_failed'
  | 'scim.group_updated'
  | 'scim.sync_completed'
  // ── §16.1 Federation (CHARIOT-SPEC.md:1347) — connected/disconnected/
  // revoked wired in FederationManager.ts; tool.dispatched/tool.denied
  // wired in the process-wide dispatch path (toolHandlers.ts). RENAMED
  // (rulings item 121): the spec's original name for this event collides
  // with a repo leak-denylist pattern (internal catalog-lifecycle
  // vocabulary that must never appear in the public tree); customer-
  // facing semantics unchanged (a kill-list entry retires an adapter
  // from the tenant's catalog), wired in KillListWatcher.ts under this
  // repo-local name — see the §20 spec-side note for the mapping.
  | 'adapter.connected'
  | 'adapter.disconnected'
  | 'adapter.revoked'
  | 'adapter.retired'
  | 'tool.dispatched'
  | 'tool.denied'
  // Pre-existing adapter-health events with no spec-§16.1 counterpart.
  | 'adapter.call_success'
  | 'adapter.call_failure'
  | 'adapter.health_check'
  | 'adapter.connectivity_lost'
  | 'adapter.connectivity_restored'
  // ── §16.1 Autonomy (CHARIOT-SPEC.md:1349) — no natural emit site closed
  // this unit; see build report. ────────────────────────────────────────
  | 'autonomy.escalated'
  | 'autonomy.approved'
  | 'autonomy.rejected'
  | 'autonomy.timed_out'
  // ── §16.1 Audit (CHARIOT-SPEC.md:1350) — no natural emit site closed
  // this unit; see build report. ────────────────────────────────────────
  | 'audit.gap_detected'
  | 'audit.export_started'
  | 'audit.export_completed'
  // Pre-existing audit events (CHARIOT::§9.8.3::4) with no spec-§16.1
  // counterpart — retained.
  | 'audit.tail_truncation_detected'
  | 'audit.attestation_unverifiable'
  // ── §16.1 Catalog (CHARIOT-SPEC.md:1351) — `catalog.signature_verified`
  // and `catalog.signature_failed` wired at src/catalog/VerifiedCatalog.ts
  // (markVerified / markFailed). `catalog.stale_warning` and
  // `catalog.refresh_completed` — no natural emit site closed this unit;
  // see build report. ───────────────────────────────────────────────────
  | 'catalog.signature_verified'
  | 'catalog.signature_failed'
  | 'catalog.stale_warning'
  | 'catalog.refresh_completed'
  // ── §16.1 Discovery (CHARIOT-SPEC.md:1352) — RENAMED from the
  // underscore forms per explicit ruling (rulings item 91). No natural
  // emit site closed this unit (nothing in src/discovery/ ever called
  // `.send()` under the old names either — see build report); declared
  // here for type-level adoption and to unblock the metrics.ts/alerts.ts
  // consumer rename. ────────────────────────────────────────────────────
  | 'discovery.scan.started'
  | 'discovery.scan.completed'
  | 'discovery.service.approved'
  | 'discovery.service.rejected'
  | 'discovery.exclusion.override'
  // ── §16.1 Operational (CHARIOT-SPEC.md:1353) — no natural emit site
  // closed this unit; see build report. ─────────────────────────────────
  | 'gateway.backend_unhealthy'
  | 'gateway.circuit_opened'
  | 'redis.unreachable'
  | 'mongo.unreachable'
  // Anomaly detection (src/observability/anomaly) — no spec-§16.1
  // counterpart, retained.
  | 'anomaly.finding'
  // System — no spec-§16.1 counterpart, retained.
  | 'system.startup'
  | 'system.shutdown'
  | 'system.error';

export interface ChariotEvent {
  type: ChariotEventType;
  timestamp: Date;
  severity: AlertSeverity;
  data: Record<string, unknown>;
  /** If true, this event should surface to the admin via the alert queue */
  alertWorthy: boolean;
  /** Human-readable message for the AI to present */
  message?: string;
  /** Recommended action for the AI to suggest */
  suggestedAction?: string;
}

export type ChariotEventCallback = (event: ChariotEvent) => void;

/**
 * Central event emitter for all Chariot subsystems.
 * Singleton — all IAM, license, vault, and adapter events flow through here.
 */
export class ChariotEmitter {
  private readonly callbacks: ChariotEventCallback[] = [];
  private readonly recentEvents: ChariotEvent[] = [];
  private readonly maxRecent = 1000;
  /** Total subscriber callback failures since process start. */
  private subscriberErrorCount = 0;
  /** Rate limiter for subscriber-error console logging. */
  private lastErrorLogMs = 0;
  private readonly ERROR_LOG_INTERVAL_MS = 60_000;

  /**
   * Subscribe to all Chariot events.
   */
  on(callback: ChariotEventCallback): this {
    this.callbacks.push(callback);
    return this;
  }

  /**
   * Unsubscribe.
   */
  off(callback: ChariotEventCallback): this {
    const idx = this.callbacks.indexOf(callback);
    if (idx !== -1) this.callbacks.splice(idx, 1);
    return this;
  }

  /**
   * Emit a Chariot event to all subscribers and the recent events buffer.
   */
  emit(event: ChariotEvent): void {
    this.recentEvents.push(event);
    if (this.recentEvents.length > this.maxRecent) {
      this.recentEvents.shift();
    }
    for (let i = 0; i < this.callbacks.length; i++) {
      const cb = this.callbacks[i];
      if (!cb) continue;
      try {
        cb(event);
      } catch (err) {
        // Never let a subscriber crash the emitter — but never swallow the
        // failure invisibly either: a persistently-throwing subscriber (e.g.
        // the alert queue) would otherwise silently drop every alert-worthy
        // event while emit() presents as success.
        this.subscriberErrorCount++;
        const now = Date.now();
        if (now - this.lastErrorLogMs >= this.ERROR_LOG_INTERVAL_MS) {
          this.lastErrorLogMs = now;
          moduleLog.error(
            `[ChariotEmitter] subscriber #${i} threw handling '${event.type}': ${String(err)} ` +
              `(${this.subscriberErrorCount} subscriber error${this.subscriberErrorCount === 1 ? '' : 's'} total; log rate-limited)`,
          );
        }
        // Surface the failure as telemetry. Recursion guard: never re-emit
        // for a system.error event, so a subscriber that throws on
        // system.error cannot cause infinite recursion (depth is capped at 2).
        if (event.type !== 'system.error') {
          this.send('system.error', {
            severity: 'warning',
            data: {
              source: 'emitter.subscriber',
              subscriberIndex: i,
              droppedEventType: event.type,
              error: String(err),
            },
          });
        }
      }
    }
  }

  /**
   * Convenience: emit with builder pattern.
   */
  send(
    type: ChariotEventType,
    opts: {
      severity?: AlertSeverity;
      data?: Record<string, unknown>;
      alertWorthy?: boolean;
      message?: string;
      suggestedAction?: string;
    } = {},
  ): void {
    this.emit({
      type,
      timestamp: new Date(),
      severity: opts.severity ?? 'info',
      data: opts.data ?? {},
      alertWorthy: opts.alertWorthy ?? false,
      message: opts.message,
      suggestedAction: opts.suggestedAction,
    });
  }

  /**
   * Get recent events, optionally filtered by type prefix.
   * This is what the AI calls to understand system state.
   */
  getRecent(filter?: string, limit = 50): ChariotEvent[] {
    let events = this.recentEvents;
    if (filter) {
      events = events.filter(e => e.type.startsWith(filter));
    }
    return events.slice(-limit);
  }

  /**
   * Get a snapshot of system state for the AI.
   * Called when the admin starts a conversation or asks "how's Chariot?"
   */
  getSystemSnapshot(): {
    recentEventCount: number;
    alertWorthyCount: number;
    lastEvent: ChariotEvent | null;
    eventCountsByType: Record<string, number>;
    /** Subscriber callback failures since process start — a non-zero,
     * growing value means a subscriber (e.g. the alert queue) is broken
     * and events are being dropped from that channel. */
    subscriberErrorCount: number;
  } {
    const counts: Record<string, number> = {};
    let alertCount = 0;

    for (const event of this.recentEvents) {
      const prefix = event.type.split('.')[0];
      counts[prefix] = (counts[prefix] ?? 0) + 1;
      if (event.alertWorthy) alertCount++;
    }

    return {
      recentEventCount: this.recentEvents.length,
      alertWorthyCount: alertCount,
      lastEvent: this.recentEvents.at(-1) ?? null,
      eventCountsByType: counts,
      subscriberErrorCount: this.subscriberErrorCount,
    };
  }
}

/**
 * Process-wide Chariot event singleton. IAM/license/vault/adapter route
 * handlers emit onto this instance (e.g. `chariotEmitter.send('auth.brute_force_lockout', ...)`)
 * — distinct from `anomalyEmitter` (src/observability/anomaly/wiring.ts),
 * which carries only `anomaly.*` findings.
 */
export const chariotEmitter = new ChariotEmitter();
