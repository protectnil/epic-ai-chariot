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
  /**
   * Presented flag for a TENANT-SCOPED alert (event.data.tenantId set —
   * only that one tenant's admin sessions ever see it, so a single flag
   * is sufficient), and for any legacy caller that reads/marks presented
   * with NO tenantId argument (e.g. anomalyAlertQueue) — unchanged
   * behavior for those callers, see presentedToTenants below.
   */
  presented: boolean;
  /**
   * CHARIOT::§16.2 step 4 (rulings item 91(2)/115(c), chariot-verify-
   * wave6 finding) — PER-TENANT presented tracking for a PROCESS-SCOPED
   * alert (event.data.tenantId absent — e.g. mongo.unreachable). A
   * process-scoped alert is delivered to EVERY tenant's admin session
   * independently (matchesTenantScope's own doc comment); tenant A's
   * admin session marking it presented must not hide it from tenant B's
   * admin session, which has not yet seen it. Only consulted when a
   * caller passes a real tenantId to getUnpresented()/markPresented() —
   * a legacy no-tenantId call still uses the single `presented` flag
   * above, preserving pre-115(c) behavior for those callers exactly.
   */
  presentedToTenants: Set<string>;
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
  /** Cap on the resolved history (oldest trimmed first). */
  private readonly MAX_RESOLVED = 500;
  /**
   * Soft cap on pending alerts. On overflow, the oldest already-presented
   * non-critical/non-urgent alerts are evicted first, then oldest presented
   * of any severity, then oldest unpresented info/warning. Unpresented
   * critical/urgent alerts are NEVER evicted — the queue may exceed the cap
   * rather than silently drop an undelivered security alert.
   */
  private readonly MAX_PENDING = 1000;
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
    // Lazily prune expired dedupe entries so the map stays bounded by the
    // number of distinct keys seen within the last window, not the total
    // distinct-entity churn over process lifetime.
    const nowMs = event.timestamp.getTime();
    for (const [k, seen] of this.dedupeWindow) {
      if (nowMs - seen.getTime() >= this.DEDUPE_MS) {
        this.dedupeWindow.delete(k);
      }
    }

    // Dedupe check — same event type + entity within window = skip
    const key = this.dedupeKey(event);
    const lastSeen = this.dedupeWindow.get(key);
    if (lastSeen && (nowMs - lastSeen.getTime()) < this.DEDUPE_MS) {
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
      presentedToTenants: new Set(),
    };

    this.pending.push(alert);
    this.evictOverflow();
    return alert;
  }

  /**
   * Keep `pending` bounded (see MAX_PENDING). Eviction preference:
   * oldest presented non-critical → oldest presented (any severity) →
   * oldest unpresented info/warning. Unpresented critical/urgent alerts
   * are never evicted. Evicted alerts also release their dedupe key so a
   * recurrence of the same event is not suppressed.
   */
  private evictOverflow(): void {
    while (this.pending.length > this.MAX_PENDING) {
      const isPushSeverity = (a: PendingAlert): boolean =>
        a.event.severity === 'critical' || a.event.severity === 'urgent';
      let idx = this.pending.findIndex(a => a.presented && !isPushSeverity(a));
      if (idx === -1) idx = this.pending.findIndex(a => a.presented);
      if (idx === -1) idx = this.pending.findIndex(a => !isPushSeverity(a));
      if (idx === -1) return; // only unpresented critical/urgent remain — never drop
      const [evicted] = this.pending.splice(idx, 1);
      if (evicted) {
        const evictedKey = this.dedupeKey(evicted.event);
        // Only clear the dedupe slot if it still belongs to this alert's window
        const seen = this.dedupeWindow.get(evictedKey);
        if (seen && seen.getTime() === evicted.event.timestamp.getTime()) {
          this.dedupeWindow.delete(evictedKey);
        }
      }
    }
  }

  /**
   * CHARIOT::§16.2 step 4 (rulings item 91(2)/115(c)) — tenant-scoping
   * predicate: an alert whose event carries NO `data.tenantId` (the
   * process-wide operational events — redis/mongo/gateway/catalog
   * unreachable/stale/etc.) is "process-scoped": operator-level, so it is
   * delivered to admin sessions of EVERY tenant. An alert that DOES carry
   * a tenantId is delivered ONLY to that tenant's own admin sessions —
   * nothing tenant-scoped ever crosses tenants. `tenantId === undefined`
   * (the caller passed no filter) preserves this class's pre-115(c)
   * behavior: every pending alert, unfiltered — used by non-tenant-aware
   * callers (anomalyAlertQueue, the pre-existing getCritical()/getCounts()
   * callers) so this change is additive, never a behavior change for them.
   */
  private matchesTenantScope(alert: PendingAlert, tenantId: string | undefined): boolean {
    if (tenantId === undefined) return true;
    const eventTenantId = alert.event.data.tenantId;
    return eventTenantId === tenantId || eventTenantId === undefined;
  }

  /**
   * CHARIOT::§16.2 step 4 (rulings item 91(2)/115(c), chariot-verify-
   * wave6 finding) — is `alert` presented FROM THE PERSPECTIVE of
   * `tenantId`? A process-scoped alert (no event.data.tenantId) uses the
   * per-tenant `presentedToTenants` set ONLY when the caller passed a
   * real tenantId — tenant A marking it presented must not hide it from
   * tenant B. A tenant-scoped alert, or ANY call with no tenantId
   * argument (legacy callers), uses the single `presented` flag —
   * unchanged behavior for both.
   */
  private isPresentedFor(alert: PendingAlert, tenantId: string | undefined): boolean {
    const eventTenantId = alert.event.data.tenantId;
    if (eventTenantId === undefined && tenantId !== undefined) {
      return alert.presentedToTenants.has(tenantId);
    }
    return alert.presented;
  }

  /**
   * Mark `alert` presented from the perspective of `tenantId` — the
   * write-side counterpart to isPresentedFor(). See that method's doc
   * comment for the exact per-tenant-vs-flag rule.
   */
  private markPresentedFor(alert: PendingAlert, tenantId: string | undefined): void {
    const eventTenantId = alert.event.data.tenantId;
    if (eventTenantId === undefined && tenantId !== undefined) {
      alert.presentedToTenants.add(tenantId);
      return;
    }
    alert.presented = true;
  }

  /**
   * Get all pending (unresolved) alerts for the AI to present, optionally
   * scoped to one tenant (CHARIOT::§16.2 step 4, rulings item 91(2)/115(c)
   * — see matchesTenantScope's doc comment for the exact scoping rule).
   *
   * PURE READ — does NOT mark alerts presented. Marking on read would
   * advance state ahead of the guarded operation: if the caller crashes or
   * the transport drops the response after this call, the alert would be
   * silently lost forever. Callers must invoke markPresented() with the
   * alert ids AFTER delivery is confirmed.
   */
  getPending(tenantId?: string): PendingAlert[] {
    return this.pending.filter(a => !a.resolvedBy && this.matchesTenantScope(a, tenantId));
  }

  /**
   * Acknowledge delivery: mark the given alerts as presented so they are
   * not repeated. Call this only AFTER the message containing them has
   * actually been delivered (at minimum, after the transport write
   * succeeded) — never before. Unknown ids are ignored.
   *
   * `tenantId` (CHARIOT::§16.2 step 4, rulings item 91(2)/115(c)) — pass
   * the SAME tenantId used for the getPending()/getUnpresented()/
   * formatForAI() call that produced these ids, so a process-scoped
   * alert is marked presented ONLY for that tenant (see isPresentedFor's
   * doc comment) — omitting it preserves the pre-115(c) single-flag
   * behavior for legacy callers.
   */
  markPresented(alertIds: string[], tenantId?: string): void {
    for (const id of alertIds) {
      const alert = this.pending.find(p => p.id === id);
      if (alert) this.markPresentedFor(alert, tenantId);
    }
  }

  /**
   * Get pending alerts that haven't been presented yet (from `tenantId`'s
   * own perspective — see isPresentedFor's doc comment), optionally
   * scoped to one tenant (see getPending()'s / matchesTenantScope's doc
   * comment). This is what the AI checks at the start of each admin
   * conversation.
   */
  getUnpresented(tenantId?: string): PendingAlert[] {
    return this.pending.filter(a => !a.resolvedBy && !this.isPresentedFor(a, tenantId) && this.matchesTenantScope(a, tenantId));
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

    // Move to resolved list (bounded: oldest trimmed on overflow)
    const idx = this.pending.indexOf(alert);
    if (idx !== -1) {
      this.pending.splice(idx, 1);
      this.resolved.push(alert);
      while (this.resolved.length > this.MAX_RESOLVED) {
        this.resolved.shift();
      }
    }

    return true;
  }

  /**
   * Mean Time To Resolve across resolved alerts — average
   * (resolvedAt - createdAt) in milliseconds. Wiz practice 7 (metrics):
   * pending/resolved counts alone don't tell an operator how fast the
   * team is actually clearing alerts; MTTR does.
   *
   * Computed over `resolved` (bounded by MAX_RESOLVED, oldest trimmed
   * first) — this is a rolling MTTR over recent history, not all-time.
   * Returns averageMs: null when no alert has ever been resolved (distinct
   * from 0 — 0 would falsely imply instant resolution).
   */
  getMTTR(): { averageMs: number | null; resolvedCount: number } {
    let totalMs = 0;
    let counted = 0;
    for (const alert of this.resolved) {
      if (alert.resolvedAt) {
        totalMs += alert.resolvedAt.getTime() - alert.createdAt.getTime();
        counted++;
      }
    }
    if (counted === 0) return { averageMs: null, resolvedCount: 0 };
    return { averageMs: Math.round(totalMs / counted), resolvedCount: counted };
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
   *
   * PURE READ — does NOT mark the alerts presented (see getPending()).
   * Returns the formatted message plus the ids it covers; the caller must
   * call markPresented(alertIds) once the message is confirmed delivered,
   * so a crash or dropped response re-surfaces the alerts next session
   * instead of silently losing them.
   */
  formatForAI(tenantId?: string): { message: string; alertIds: string[] } | null {
    const unpresented = this.getUnpresented(tenantId);
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

    return {
      message: lines.join('\n'),
      alertIds: unpresented.map(a => a.id),
    };
  }
}

/**
 * CHARIOT::§16.2 (rulings item 91(2)/105) — the process-wide AlertQueue for
 * every chariotEmitter alert-worthy event (distinct from
 * src/observability/anomaly/wiring.ts's `anomalyAlertQueue`, which is
 * subscribed to the SEPARATE `anomalyEmitter`, not `chariotEmitter`).
 * `src/observability/alertDispatchWiring.ts`'s `wireAlertDispatch()`
 * enqueues into this instance for the §16.2 step-4 conversational-queue
 * fallback; `src/engine/bin/setup.ts` wires it at boot.
 */
export const chariotAlertQueue = new AlertQueue();
