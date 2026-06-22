/**
 * Chariot Event Emitter
 *
 * Structured event system for Chariot-specific telemetry.
 * Events flow to: the AI (via MCP tools), the alert queue,
 * the metrics aggregator, and optionally to external systems.
 */

export type AlertSeverity = 'info' | 'warning' | 'urgent' | 'critical';

export type ChariotEventType =
  // License
  | 'license.checked'
  | 'license.state_changed'
  | 'license.renewal_attempted'
  | 'license.renewal_succeeded'
  | 'license.renewal_failed'
  // IAM Sessions
  | 'session.created'
  | 'session.revoked'
  | 'session.expired'
  | 'session.auth_failed'
  | 'session.brute_force_detected'
  // RBAC
  | 'rbac.access_granted'
  | 'rbac.access_denied'
  | 'rbac.mapping_changed'
  // Credential Vault
  | 'vault.credential_connected'
  | 'vault.credential_revoked'
  | 'vault.credential_expiring'
  | 'vault.encrypt'
  | 'vault.decrypt'
  // SCIM
  | 'scim.user_provisioned'
  | 'scim.user_deprovisioned'
  | 'scim.group_updated'
  | 'scim.sync_completed'
  // Adapter Health
  | 'adapter.call_success'
  | 'adapter.call_failure'
  | 'adapter.health_check'
  | 'adapter.connectivity_lost'
  | 'adapter.connectivity_restored'
  // Discovery
  | 'discovery.scan_started'
  | 'discovery.scan_completed'
  | 'discovery.service_approved'
  | 'discovery.service_rejected'
  // System
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
    for (const cb of this.callbacks) {
      try {
        cb(event);
      } catch {
        // Never let a subscriber crash the emitter
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
    };
  }
}
