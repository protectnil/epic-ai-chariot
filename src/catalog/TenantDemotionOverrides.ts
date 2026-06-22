/**
 * @epicai/chariot — Per-tenant demotion override store (C3, 2026-04-12)
 *
 * A tenant admin may explicitly override an upstream
 * catalog demotion for a single adapter on their tenant. The
 * override is audited, time-bounded, and narrowly scoped —
 * it does NOT re-verify the adapter, it just exempts it
 * from the C2 failed-catalog filter for the duration of
 * the override.
 *
 * Use case: the upstream catalog publisher demotes
 * `stripe-test-sandbox` because of a probe failure. The
 * tenant's billing flow can't tolerate losing Stripe access.
 * The tenant admin issues
 * an override with a business-justification note and a
 * 24-hour expiry. The middleware C2 layer (C3 integration)
 * then exempts `stripe-test-sandbox` from the failed set
 * for that tenant until the override expires or is
 * revoked.
 *
 * Overrides are PER-TENANT. An override on tenant A does
 * not affect tenant B. The store is purely in-memory for
 * this PR — a persistence adapter for Mongo is a follow-up.
 *
 * All overrides are visible on the public `/overrides`
 * surface per spec §10.10, with the full audit trail.
 */

import { canonicalName } from './VerifiedCatalog.js';

// ─── Types ───────────────────────────────────────────────────────────────

export interface TenantDemotionOverride {
  tenantId: string;
  /** Canonicalized adapter name. */
  adapterName: string;
  /** Who issued the override (tenant admin login). */
  issuedBy: string;
  /** When the override was issued. */
  issuedAt: Date;
  /** When the override expires (after which it no longer exempts). */
  expiresAt: Date;
  /** Business justification. Required. Surfaced on /overrides. */
  justification: string;
  /** When the override was revoked (null if still active). */
  revokedAt: Date | null;
  revokedBy?: string;
}

export interface IssueOverrideInputs {
  tenantId: string;
  adapterName: string;
  issuedBy: string;
  issuedAt: Date;
  /** Override duration in milliseconds. */
  durationMs: number;
  justification: string;
}

// ─── Tunables ───────────────────────────────────────────────────────────

/**
 * Hard ceiling on override duration. A tenant admin cannot
 * issue an override longer than this — spec §10.10 requires
 * overrides to be "rare and auditable", and permanent
 * overrides would defeat the trust layer entirely.
 */
export const MAX_OVERRIDE_DURATION_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * Minimum justification length. Empty/whitespace
 * justifications are rejected — the override record is
 * public-facing, so "ok" is not an acceptable reason.
 */
export const MIN_JUSTIFICATION_LENGTH = 20;

// ─── Store ──────────────────────────────────────────────────────────────

/**
 * In-memory store of per-tenant demotion overrides.
 *
 * Append-only history model: every `issue()` call pushes a
 * new record onto the full history array. `revoke()` does
 * NOT delete the record, it stamps `revokedAt` on it in
 * place. A reissue on the same (tenantId, adapter) pair
 * creates a NEW record with its own lifecycle; the prior
 * record remains in the history for audit purposes.
 *
 * `get()` / `isExempted()` walk the history and return the
 * most recently issued record that is currently active
 * (unrevoked and unexpired). Lookups stay O(n) in the
 * worst case but the expected size is small — overrides
 * are rare per spec §10.10.
 *
 * A follow-up PR will add a Mongo persistence adapter so
 * overrides survive process restart.
 */
export class TenantDemotionOverrideStore {
  private readonly history: TenantDemotionOverride[] = [];

  /**
   * Issue a new override. Throws if the duration exceeds
   * the ceiling or the justification is too short. Always
   * appends to the history; never mutates prior records.
   */
  issue(inputs: IssueOverrideInputs): TenantDemotionOverride {
    if (inputs.durationMs <= 0) {
      throw new Error('override duration must be positive');
    }
    if (inputs.durationMs > MAX_OVERRIDE_DURATION_MS) {
      throw new Error(
        `override duration exceeds ceiling (${MAX_OVERRIDE_DURATION_MS}ms)`,
      );
    }
    const justification = (inputs.justification ?? '').trim();
    if (justification.length < MIN_JUSTIFICATION_LENGTH) {
      throw new Error(
        `override justification must be at least ${MIN_JUSTIFICATION_LENGTH} chars`,
      );
    }
    const canonical = canonicalName(inputs.adapterName);
    const record: TenantDemotionOverride = {
      tenantId: inputs.tenantId,
      adapterName: canonical,
      issuedBy: inputs.issuedBy,
      issuedAt: inputs.issuedAt,
      expiresAt: new Date(inputs.issuedAt.getTime() + inputs.durationMs),
      justification,
      revokedAt: null,
    };
    this.history.push(record);
    return record;
  }

  /**
   * Look up the current override for a (tenant, adapter)
   * pair. Returns the MOST RECENT active record, if any.
   * Returns null when no active record exists (never
   * issued, expired, or revoked).
   */
  get(
    tenantId: string,
    adapterName: string,
    now: Date,
  ): TenantDemotionOverride | null {
    const canonical = canonicalName(adapterName);
    // Walk the history in reverse so the most-recent entry
    // is checked first.
    for (let i = this.history.length - 1; i >= 0; i--) {
      const record = this.history[i];
      if (!record) continue;
      if (record.tenantId !== tenantId) continue;
      if (record.adapterName !== canonical) continue;
      if (record.revokedAt) continue;
      if (record.expiresAt.getTime() <= now.getTime()) continue;
      return record;
    }
    return null;
  }

  /**
   * Check whether an adapter is currently exempted for a
   * tenant. Convenience wrapper on `get()`.
   */
  isExempted(tenantId: string, adapterName: string, now: Date): boolean {
    return this.get(tenantId, adapterName, now) !== null;
  }

  /**
   * Revoke the currently-active override for a (tenant,
   * adapter) pair. Idempotent — if no active (unrevoked,
   * unexpired) override exists, it's a no-op. A newer
   * record that is already expired or already revoked is
   * SKIPPED: revoke() walks the history looking for the
   * most recent record that is still active and stamps
   * that one. Older entries remain historical and are
   * never mutated.
   */
  revoke(
    tenantId: string,
    adapterName: string,
    revokedBy: string,
    revokedAt: Date,
  ): void {
    const canonical = canonicalName(adapterName);
    for (let i = this.history.length - 1; i >= 0; i--) {
      const record = this.history[i];
      if (!record) continue;
      if (record.tenantId !== tenantId) continue;
      if (record.adapterName !== canonical) continue;
      if (record.revokedAt) continue; // not active; keep walking
      if (record.expiresAt.getTime() <= revokedAt.getTime()) {
        continue; // already expired; keep walking
      }
      record.revokedAt = revokedAt;
      record.revokedBy = revokedBy;
      return;
    }
  }

  /**
   * List all currently-active overrides for a tenant.
   * Walks the full history and returns at most one record
   * per (tenant, adapter) pair — the most recent one that
   * is still ACTIVE. Expired or revoked records do not
   * consume the dedup slot, so an older active override
   * still surfaces even if a newer revoked/expired record
   * exists for the same adapter.
   */

  /**
   * List all currently-active overrides for a tenant.
   * Deduplicates by (tenant, adapter) — if history has
   * multiple reissues of the same adapter, only the most
   * recent active one is returned. Used by the tenant
   * admin UI + the public /overrides surface's "active"
   * section.
   */
  listActive(tenantId: string, now: Date): TenantDemotionOverride[] {
    const seen = new Set<string>();
    const results: TenantDemotionOverride[] = [];
    // Walk in reverse so the most-recent ACTIVE record
    // wins per adapter. A newer expired or revoked record
    // does NOT claim the dedup slot — we keep walking
    // until we find an active record (or run out).
    for (let i = this.history.length - 1; i >= 0; i--) {
      const record = this.history[i];
      if (!record) continue;
      if (record.tenantId !== tenantId) continue;
      if (seen.has(record.adapterName)) continue;
      if (record.revokedAt) continue;
      if (record.expiresAt.getTime() <= now.getTime()) continue;
      // Only mark as "seen" once we've confirmed this
      // record is actually active. Otherwise an older
      // active record for the same adapter would be
      // suppressed by a newer inactive one.
      seen.add(record.adapterName);
      results.push(record);
    }
    return results;
  }

  /**
   * List EVERY override (active, expired, revoked, and
   * historical reissues) for a tenant in chronological
   * order. Used by the public /overrides page per spec
   * §10.10 to show the full audit trail including the
   * lifecycle of every issuance and revocation.
   */
  listAll(tenantId: string): TenantDemotionOverride[] {
    return this.history.filter((r) => r.tenantId === tenantId);
  }
}
