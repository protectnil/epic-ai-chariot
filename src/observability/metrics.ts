/**
 * Chariot Metrics Aggregator
 *
 * Computes rolling metrics from the event stream for the AI to report.
 * These power the admin's "how's Chariot?" query and the executive digest.
 */

import type { ChariotEvent, ChariotEventCallback } from './emitter.js';
import { getRegisteredTokenUsageSource } from './tokenUsageRegistry.js';

/**
 * CHARIOT::§16.3::1 — structural mirror of TokenTracker's CostSummary
 * .byAdapter dimension (src/engine/observability/TokenTracker.ts:59-69),
 * defined here rather than imported so this module has zero dependency
 * on TokenTracker.ts. See the tokenUsageSource field doc comment below.
 */
export interface TokenUsageByAdapterSource {
  getTokenUsageByAdapter(): Record<string, { tokens: number; costUsd: number }>;
}

interface AdapterStats {
  totalCalls: number;
  failures: number;
  lastCallAt: Date | null;
  lastFailureAt: Date | null;
  totalDurationMs: number;
}

/**
 * Aggregates Chariot events into queryable metrics.
 * Subscribe this to ChariotEmitter to keep metrics current.
 */
export class ChariotMetrics implements Record<string, unknown> {
  [key: string]: unknown;

  // License
  licenseState: string = 'unknown';
  licenseLastChecked: Date | null = null;
  renewalAttempts = 0;
  renewalFailures = 0;

  // Sessions
  sessionsCreated = 0;
  sessionsRevoked = 0;
  authFailures = 0;
  bruteForceEvents = 0;

  // RBAC
  accessGranted = 0;
  accessDenied = 0;
  mappingChanges = 0;

  // Vault
  credentialsConnected = 0;
  credentialsRevoked = 0;
  credentialsExpiring = 0;
  vaultOperations = 0;

  // SCIM
  usersProvisioned = 0;
  usersDeprovisioned = 0;
  scimSyncs = 0;

  // Adapters
  private adapterStats = new Map<string, AdapterStats>();

  // Discovery
  scansCompleted = 0;
  servicesApproved = 0;
  servicesRejected = 0;

  // CHARIOT::§16.3::1 (CHARIOT-SPEC.md:1372, rulings item 91(3)) — "Per-tier
  // autonomy decisions." Tiers are TieredAutonomy.ts's own `auto` /
  // `escalate` / `approve` classification (CHARIOT-SPEC.md:88, :553), NOT
  // the unrelated Tier-1/Tier-2 routing pipeline (§4). Fed by the
  // `autonomy.escalated`/`approved`/`rejected`/`timed_out` §16.1 events
  // (CHARIOT-SPEC.md:1348) via `event.data.tier` — no natural emit site for
  // those four events was wired in this unit (see the build report's
  // "could not close" section), so these counters read zero in production
  // until that wiring lands; the ingest()/getSummary() shape is complete
  // and ready to receive them.
  private autonomyByTier = { auto: 0, escalate: 0, approve: 0 };
  private autonomyEscalated = 0;
  private autonomyApproved = 0;
  private autonomyRejected = 0;
  private autonomyTimedOut = 0;

  // CHARIOT::§16.3::1 (CHARIOT-SPEC.md:1373, rulings item 91(3)) — "Token
  // usage by adapter (from §8.12 TokenTracker)." Structural interface
  // mirroring TokenTracker's own CostSummary.byAdapter dimension
  // (src/engine/observability/TokenTracker.ts:59-69) WITHOUT importing
  // that file. TWO wiring paths, in priority order:
  //   1. `this.tokenUsageSource` — an explicit per-instance override set
  //      via setTokenUsageSource() below.
  //   2. `tokenUsageRegistry.ts`'s process-wide registration — EpicAI's
  //      constructor registers itself there, so ANY ChariotMetrics
  //      instance in the same process picks it up automatically with no
  //      second wiring call (gate finding 114(i), W34-4c).
  // getSummary() falls back to the registry only when NO explicit source
  // was set on THIS instance — an explicit setTokenUsageSource() call
  // always wins. When neither is present, tokenUsageByAdapter reports the
  // honest `{ available: false, reason: '...' }` marker (see getSummary())
  // instead of a silently-empty `{}` — a caller must be able to tell
  // "genuinely zero token usage recorded" apart from "no orchestrator in
  // this process at all."
  private tokenUsageSource: TokenUsageByAdapterSource | null = null;

  /**
   * Explicitly inject a token-usage-by-adapter source for THIS
   * ChariotMetrics instance, overriding the process-wide registry (see the
   * tokenUsageSource field doc comment above).
   */
  setTokenUsageSource(source: TokenUsageByAdapterSource): void {
    this.tokenUsageSource = source;
  }

  /**
   * CHARIOT::§16.3::1 / gate finding 114(i) — explicit per-instance source
   * wins; otherwise fall back to the process-wide registry (an EpicAI
   * instance constructed anywhere in this process); otherwise report the
   * honest absence marker instead of a silent `{}`.
   */
  private resolveTokenUsageByAdapter(): Record<string, { tokens: number; costUsd: number }> | { available: false; reason: string } {
    const source = this.tokenUsageSource ?? getRegisteredTokenUsageSource();
    if (!source) {
      return { available: false, reason: 'no orchestrator in this process' };
    }
    return source.getTokenUsageByAdapter();
  }

  // CHARIOT::§16.2 (rulings item 91(2)/105/114(d), review gate finding (d))
  // — "count it in ChariotMetrics as a dispatch failure for that channel."
  // Fed by createFederationAlertDispatcher (alertDispatchWiring.ts) when a
  // channel is skipped for lack of configuration (CHARIOT_ALERT_EMAIL_FROM
  // / CHARIOT_ALERT_PAGERDUTY_SERVICE_ID unset) — a real per-channel
  // dispatch failure, distinct from a genuine transport-level error
  // (which the caller handles via onDispatchError and does not count
  // here, since that is not "unconfigured", it is "configured but failed").
  private alertDispatchSkipped: { slack: number; email: number; pagerduty: number } = { slack: 0, email: 0, pagerduty: 0 };

  /** Record a channel dispatch skipped for lack of configuration. */
  recordAlertDispatchSkipped(channel: 'slack' | 'email' | 'pagerduty'): void {
    this.alertDispatchSkipped[channel]++;
  }

  // Supply-chain integrity (Wiz practice 7 — metrics). Observability does
  // NOT itself verify adapter signatures/attestations — that is the
  // catalog trust module's job (src/catalog/VerifiedCatalog.ts). This is
  // just the feed point: the verifier calls setSupplyChainIntegrity() with
  // its own verified/total counts (e.g. from allVerifications().filter(r =>
  // r.status === 'verified').length vs allVerifications().length) and this
  // class exposes the computed percentage on the summary.
  private supplyChainVerifiedCount = 0;
  private supplyChainTotalCount = 0;

  /**
   * Feed verified/total adapter counts from the catalog trust verifier.
   * Counts, not booleans — total may exceed verified (failed/pending/stale
   * adapters lower the percentage, exactly the signal Wiz practice 7 wants
   * surfaced). Call this whenever the verifier's view of the catalog
   * changes (e.g. after a verification pass or catalog reload).
   */
  setSupplyChainIntegrity(verifiedCount: number, totalCount: number): void {
    this.supplyChainVerifiedCount = verifiedCount;
    this.supplyChainTotalCount = totalCount;
  }

  /**
   * Percentage (0-100, 2 decimal places) of loaded adapters whose
   * signature/attestation verified. Null when no counts have been fed yet
   * (distinct from 0% — 0% means "fed and all failed," null means
   * "verifier hasn't reported in").
   */
  getSupplyChainIntegrityPercent(): number | null {
    if (this.supplyChainTotalCount === 0) return null;
    return Math.round((this.supplyChainVerifiedCount / this.supplyChainTotalCount) * 10000) / 100;
  }

  /**
   * Returns a callback suitable for ChariotEmitter.on().
   */
  asCallback(): ChariotEventCallback {
    return (event: ChariotEvent) => this.ingest(event);
  }

  /**
   * Process a single event and update metrics.
   */
  ingest(event: ChariotEvent): void {
    switch (event.type) {
      // License
      case 'license.checked':
        this.licenseLastChecked = event.timestamp;
        if (event.data.state) this.licenseState = event.data.state as string;
        break;
      case 'license.state_changed':
        this.licenseState = (event.data.newState as string) ?? 'unknown';
        break;
      case 'license.renewal_attempted':
        this.renewalAttempts++;
        break;
      case 'license.renewal_succeeded':
        break;
      case 'license.renewal_failed':
        this.renewalFailures++;
        break;

      // Sessions
      case 'session.created':
        this.sessionsCreated++;
        break;
      case 'session.revoked':
        this.sessionsRevoked++;
        break;
      case 'session.auth_failed':
        this.authFailures++;
        break;
      case 'session.brute_force_detected':
        this.bruteForceEvents++;
        break;

      // RBAC
      case 'rbac.access_granted':
        this.accessGranted++;
        break;
      case 'rbac.access_denied':
        this.accessDenied++;
        break;
      case 'rbac.mapping_changed':
        this.mappingChanges++;
        break;

      // Vault
      case 'vault.credential_connected':
        this.credentialsConnected++;
        break;
      case 'vault.credential_revoked':
        this.credentialsRevoked++;
        break;
      case 'vault.credential_expiring':
        this.credentialsExpiring++;
        break;
      case 'vault.encrypt':
      case 'vault.decrypt':
        this.vaultOperations++;
        break;

      // SCIM
      case 'scim.user_provisioned':
        this.usersProvisioned++;
        break;
      case 'scim.user_deprovisioned':
        this.usersDeprovisioned++;
        break;
      case 'scim.sync_completed':
        this.scimSyncs++;
        break;

      // Adapters
      case 'adapter.call_success':
      case 'adapter.call_failure': {
        const adapterId = (event.data.adapterId as string) ?? 'unknown';
        const stats = this.getAdapterStats(adapterId);
        stats.totalCalls++;
        stats.lastCallAt = event.timestamp;
        if (event.type === 'adapter.call_failure') {
          stats.failures++;
          stats.lastFailureAt = event.timestamp;
        }
        if (typeof event.data.durationMs === 'number') {
          stats.totalDurationMs += event.data.durationMs;
        }
        break;
      }

      // Autonomy — CHARIOT::§16.3::1 (rulings item 91(3)). `event.data.tier`
      // is expected to be one of TieredAutonomy's own three tier strings
      // ('auto'|'escalate'|'approve'); an event carrying an unrecognized or
      // absent tier still increments the top-level counter (the decision
      // happened) but is not double-counted into byTier — ABSENT tier data
      // is unknown, never coerced into one of the three named buckets.
      case 'autonomy.escalated':
        this.autonomyEscalated++;
        this.tallyAutonomyTier(event.data.tier);
        break;
      case 'autonomy.approved':
        this.autonomyApproved++;
        this.tallyAutonomyTier(event.data.tier);
        break;
      case 'autonomy.rejected':
        this.autonomyRejected++;
        this.tallyAutonomyTier(event.data.tier);
        break;
      case 'autonomy.timed_out':
        this.autonomyTimedOut++;
        this.tallyAutonomyTier(event.data.tier);
        break;

      // Discovery — CHARIOT::§16.1 Discovery (CHARIOT-SPEC.md:1352, rulings
      // item 91): renamed from the underscore forms (`discovery.scan_
      // completed` etc.) to the spec's dotted forms.
      case 'discovery.scan.completed':
        this.scansCompleted++;
        break;
      case 'discovery.service.approved':
        this.servicesApproved++;
        break;
      case 'discovery.service.rejected':
        this.servicesRejected++;
        break;
    }
  }

  private tallyAutonomyTier(tier: unknown): void {
    if (tier === 'auto' || tier === 'escalate' || tier === 'approve') {
      this.autonomyByTier[tier]++;
    }
  }

  /**
   * CHARIOT::§16.3::1 pending-approvals count: decisions escalated for
   * human review that have not yet resolved (approved/rejected/timed out).
   * Floored at 0 — a resolution event for a decision this aggregator never
   * saw escalate (e.g. this instance started after the escalation) must
   * not drive the count negative.
   */
  getPendingApprovals(): number {
    return Math.max(0, this.autonomyEscalated - this.autonomyApproved - this.autonomyRejected - this.autonomyTimedOut);
  }

  private getAdapterStats(adapterId: string): AdapterStats {
    let stats = this.adapterStats.get(adapterId);
    if (!stats) {
      stats = { totalCalls: 0, failures: 0, lastCallAt: null, lastFailureAt: null, totalDurationMs: 0 };
      this.adapterStats.set(adapterId, stats);
    }
    return stats;
  }

  /**
   * Get per-adapter health summary for the AI.
   */
  getAdapterHealth(): Array<{
    adapterId: string;
    totalCalls: number;
    failures: number;
    errorRate: number;
    avgLatencyMs: number;
    lastCallAt: string | null;
    lastFailureAt: string | null;
  }> {
    const result: Array<{
      adapterId: string;
      totalCalls: number;
      failures: number;
      errorRate: number;
      avgLatencyMs: number;
      lastCallAt: string | null;
      lastFailureAt: string | null;
    }> = [];

    for (const [adapterId, stats] of this.adapterStats) {
      result.push({
        adapterId,
        totalCalls: stats.totalCalls,
        failures: stats.failures,
        errorRate: stats.totalCalls > 0 ? stats.failures / stats.totalCalls : 0,
        avgLatencyMs: stats.totalCalls > 0 ? Math.round(stats.totalDurationMs / stats.totalCalls) : 0,
        lastCallAt: stats.lastCallAt?.toISOString() ?? null,
        lastFailureAt: stats.lastFailureAt?.toISOString() ?? null,
      });
    }

    return result.sort((a, b) => b.errorRate - a.errorRate);
  }

  /**
   * Generate the summary the AI uses when asked "how's Chariot?"
   * or for the executive weekly digest.
   */
  getSummary(): {
    license: { state: string; lastChecked: string | null; renewalAttempts: number; renewalFailures: number };
    sessions: { created: number; revoked: number; authFailures: number; bruteForceEvents: number };
    rbac: { granted: number; denied: number; mappingChanges: number };
    vault: { connected: number; revoked: number; expiring: number; operations: number };
    scim: { provisioned: number; deprovisioned: number; syncs: number };
    adapters: { total: number; withErrors: number; topErrors: Array<{ adapterId: string; errorRate: number }> };
    discovery: { scans: number; approved: number; rejected: number };
    supplyChain: { verifiedCount: number; totalCount: number; integrityPercent: number | null };
    autonomy: {
      pendingApprovals: number;
      byTier: { auto: number; escalate: number; approve: number };
      escalated: number;
      approved: number;
      rejected: number;
      timedOut: number;
    };
    // CHARIOT::§16.3::1 / gate finding 114(i) — honest absence marker. A
    // Record means real (possibly zero-entry-but-genuinely-measured) data;
    // `{available:false}` means no TokenTracker source has EVER registered
    // in this process (distinct from "registered but recorded nothing
    // yet," which would still surface as an empty Record `{}` here since
    // TokenTracker.summary().byAdapter itself returns `{}` for zero
    // entries — that is real, not absent, and is not this marker's case).
    tokenUsageByAdapter: Record<string, { tokens: number; costUsd: number }> | { available: false; reason: string };
    alertDispatch: { skipped: { slack: number; email: number; pagerduty: number } };
  } {
    const adapterHealth = this.getAdapterHealth();

    return {
      license: {
        state: this.licenseState,
        lastChecked: this.licenseLastChecked?.toISOString() ?? null,
        renewalAttempts: this.renewalAttempts,
        renewalFailures: this.renewalFailures,
      },
      sessions: {
        created: this.sessionsCreated,
        revoked: this.sessionsRevoked,
        authFailures: this.authFailures,
        bruteForceEvents: this.bruteForceEvents,
      },
      rbac: {
        granted: this.accessGranted,
        denied: this.accessDenied,
        mappingChanges: this.mappingChanges,
      },
      vault: {
        connected: this.credentialsConnected,
        revoked: this.credentialsRevoked,
        expiring: this.credentialsExpiring,
        operations: this.vaultOperations,
      },
      scim: {
        provisioned: this.usersProvisioned,
        deprovisioned: this.usersDeprovisioned,
        syncs: this.scimSyncs,
      },
      adapters: {
        total: this.adapterStats.size,
        withErrors: adapterHealth.filter(a => a.failures > 0).length,
        topErrors: adapterHealth.filter(a => a.errorRate > 0).slice(0, 5).map(a => ({
          adapterId: a.adapterId,
          errorRate: Math.round(a.errorRate * 100) / 100,
        })),
      },
      discovery: {
        scans: this.scansCompleted,
        approved: this.servicesApproved,
        rejected: this.servicesRejected,
      },
      supplyChain: {
        verifiedCount: this.supplyChainVerifiedCount,
        totalCount: this.supplyChainTotalCount,
        integrityPercent: this.getSupplyChainIntegrityPercent(),
      },
      autonomy: {
        pendingApprovals: this.getPendingApprovals(),
        byTier: { ...this.autonomyByTier },
        escalated: this.autonomyEscalated,
        approved: this.autonomyApproved,
        rejected: this.autonomyRejected,
        timedOut: this.autonomyTimedOut,
      },
      tokenUsageByAdapter: this.resolveTokenUsageByAdapter(),
      alertDispatch: { skipped: { ...this.alertDispatchSkipped } },
    };
  }
}
