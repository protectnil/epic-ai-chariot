/**
 * Chariot Alert Queue
 *
 * Accumulates alert-worthy events for the AI to surface proactively.
 * When the admin next interacts with Chariot through their AI client,
 * pending alerts are presented at the start of the conversation.
 *
 * Spec reference: Chapter 4 (Alert Architecture), Chapter 9 (Channel Strategy)
 *
 * Rules from spec:
 * 1. Never duplicate — same event type not repeated until situation changes
 * 2. Never cascade — 50 users hitting seat limit = 1 alert, not 50
 * 3. Batch info-level — wait for next admin session or daily digest
 * 4. Immediate only for security — brute force, audit chain failure
 * 5. Every alert includes the action — never inform without a next step
 */

import type { ChariotEvent, ChariotEventCallback, AlertSeverity } from './emitter.js';

export interface PendingAlert {
  id: string;
  event: ChariotEvent;
  createdAt: Date;
  resolvedBy: string | null;
  resolvedAt: Date | null;
  presented: boolean;
}

/**
 * Alert queue that feeds the AI's proactive awareness.
 * Subscribe to ChariotEmitter to automatically queue alert-worthy events.
 */
export class AlertQueue {
  private readonly pending: PendingAlert[] = [];
  private readonly resolved: PendingAlert[] = [];
  private readonly dedupeWindow = new Map<string, Date>();
  private readonly DEDUPE_MS = 3600_000; // 1 hour dedupe window
  private nextId = 1;

  /**
   * Returns a callback suitable for ChariotEmitter.on().
   */
  asCallback(): ChariotEventCallback {
    return (event: ChariotEvent) => {
      if (event.alertWorthy) {
        this.enqueue(event);
      }
    };
  }

  /**
   * Add an alert-worthy event to the queue.
   * Deduplicates by event type within a 1-hour window.
   */
  /**
   * Build a dedupe key from event type + entity identifier.
   * e.g. "adapter.connectivity_lost:datadog" vs "adapter.connectivity_lost:github"
   * Falls back to event type alone if no entity is present.
   */
  private dedupeKey(event: ChariotEvent): string {
    const entity = (event.data.adapterId as string)
      ?? (event.data.userId as string)
      ?? (event.data.tenantId as string)
      ?? (event.data.serviceId as string)
      ?? '';
    return entity ? `${event.type}:${entity}` : event.type;
  }

  enqueue(event: ChariotEvent): PendingAlert | null {
    // Dedupe check — same event type + entity within window = skip
    const key = this.dedupeKey(event);
    const lastSeen = this.dedupeWindow.get(key);
    if (lastSeen && (event.timestamp.getTime() - lastSeen.getTime()) < this.DEDUPE_MS) {
      return null;
    }

    this.dedupeWindow.set(key, event.timestamp);

    const alert: PendingAlert = {
      id: `alert-${this.nextId++}`,
      event,
      createdAt: event.timestamp,
      resolvedBy: null,
      resolvedAt: null,
      presented: false,
    };

    this.pending.push(alert);
    return alert;
  }

  /**
   * Get all pending (unresolved) alerts for the AI to present.
   * Marks them as presented so they aren't repeated.
   */
  getPending(): PendingAlert[] {
    const alerts = this.pending.filter(a => !a.resolvedBy);
    for (const alert of alerts) {
      alert.presented = true;
    }
    return alerts;
  }

  /**
   * Get pending alerts that haven't been presented yet.
   * This is what the AI checks at the start of each admin conversation.
   */
  getUnpresented(): PendingAlert[] {
    return this.pending.filter(a => !a.resolvedBy && !a.presented);
  }

  /**
   * Get only critical/urgent alerts (for immediate push channels).
   */
  getCritical(): PendingAlert[] {
    return this.pending.filter(
      a => !a.resolvedBy && (a.event.severity === 'critical' || a.event.severity === 'urgent'),
    );
  }

  /**
   * Resolve an alert. First admin to act resolves it for all.
   * Spec: "Resolved by [admin name] N minutes ago" shown to other admins.
   */
  resolve(alertId: string, adminId: string): boolean {
    const alert = this.pending.find(a => a.id === alertId);
    if (!alert || alert.resolvedBy) return false;

    alert.resolvedBy = adminId;
    alert.resolvedAt = new Date();

    // Clear dedupe so a real recurrence of the same event + entity is not suppressed
    this.dedupeWindow.delete(this.dedupeKey(alert.event));

    // Move to resolved list
    const idx = this.pending.indexOf(alert);
    if (idx !== -1) {
      this.pending.splice(idx, 1);
      this.resolved.push(alert);
    }

    return true;
  }

  /**
   * Get the count of pending alerts by severity.
   * Quick check for the AI to decide whether to proactively surface alerts.
   */
  getCounts(): Record<AlertSeverity, number> {
    const counts: Record<AlertSeverity, number> = { info: 0, warning: 0, urgent: 0, critical: 0 };
    for (const alert of this.pending) {
      if (!alert.resolvedBy) {
        counts[alert.event.severity]++;
      }
    }
    return counts;
  }

  /**
   * Format pending alerts as a message the AI can present to the admin.
   * Spec Ch9: "Before we start — N items need your attention..."
   */
  formatForAI(): string | null {
    const unpresented = this.getUnpresented();
    if (unpresented.length === 0) return null;

    const lines: string[] = [];
    lines.push(`Before we start — ${unpresented.length} item${unpresented.length > 1 ? 's' : ''} need${unpresented.length === 1 ? 's' : ''} your attention:\n`);

    for (let i = 0; i < unpresented.length; i++) {
      const alert = unpresented[i];
      const msg = alert.event.message ?? alert.event.type;
      const action = alert.event.suggestedAction ? ` ${alert.event.suggestedAction}` : '';
      lines.push(`${i + 1}. ${msg}${action}`);
    }

    lines.push('\nEverything else is running normally.');

    // Mark as presented
    for (const alert of unpresented) {
      alert.presented = true;
    }

    return lines.join('\n');
  }
}
