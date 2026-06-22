/**
 * Chariot Metrics Aggregator
 *
 * Computes rolling metrics from the event stream for the AI to report.
 * These power the admin's "how's Chariot?" query and the executive digest.
 */

import type { ChariotEvent, ChariotEventCallback } from './emitter.js';

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

      // Discovery
      case 'discovery.scan_completed':
        this.scansCompleted++;
        break;
      case 'discovery.service_approved':
        this.servicesApproved++;
        break;
      case 'discovery.service_rejected':
        this.servicesRejected++;
        break;
    }
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
    };
  }
}
