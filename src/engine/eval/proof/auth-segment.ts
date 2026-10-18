/**
 * Epic AI® Chariot — Routing Proof-Artifact Eval: requiresCustomerAuth segment
 *
 * CHARIOT-SPEC §4.5: "The gold set MUST include `requiresCustomerAuth`
 * adapters (AS §1.2a) — server-level and capability-tag queries — and report
 * `Recall@8` for that class separately, so auth-walled discovery reliability
 * is a measured, bounded number, not an assumed one (no silent tail)."
 *
 * This module segments the already-scored gold-set PerQueryResults into that
 * class and reports Recall@8 for it distinctly from the pooled headline.
 * `aggregate()` (scoring.ts) is reused unmodified — this is composition, not
 * a second scoring implementation.
 *
 * Fails LOUD, never silent: `run-proof.ts` currently measures against a
 * production catalog that carries ZERO `requiresCustomerAuth:true` adapters
 * (verified 2026-07-30 — the field does not appear anywhere in
 * chariot-adapter-bundle.json / chariot-adapter-catalog.json, nor did the
 * `AdapterEntry`/`AdapterCatalogEntry` types carry it before this change).
 * That is a catalog-population gap, not a gold-set gap, and this module
 * reports it as exactly that — never as a fabricated 0/0 "measured" recall
 * and never omitted from the artifact.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { aggregate } from './scoring.js';
import type { PerQueryResult, RequiresCustomerAuthSegmentReport } from './types.js';

/**
 * Segment already-scored PerQueryResults into the requiresCustomerAuth
 * subset (§4.5). A query is IN the subset when at least one of its labeled
 * `relevantToolIds` belongs to a `requiresCustomerAuth:true` adapter
 * (`requiresCustomerAuthToolIds`, built in catalog.ts by joining tool ids
 * back to their owning adapter's flag).
 */
export function buildRequiresCustomerAuthSegment(
  perQuery: readonly PerQueryResult[],
  requiresCustomerAuthToolIds: ReadonlySet<string>,
  requiresCustomerAuthAdapterCount: number,
  k: number,
  recallFloor: number,
): RequiresCustomerAuthSegmentReport {
  const subset = perQuery.filter((r) =>
    r.relevantToolIds.some((id) => requiresCustomerAuthToolIds.has(id)),
  );

  if (requiresCustomerAuthAdapterCount === 0) {
    return {
      adapterCount: 0,
      queryCount: 0,
      status: 'no-adapters-present',
      reason:
        'CHARIOT-SPEC §4.5 / AS §1.2a: the catalog under test carries ZERO adapters flagged ' +
        'requiresCustomerAuth:true. The gold set cannot include this class because the catalog ' +
        'contains no such adapter to label against. This is a CATALOG-POPULATION gap, not a ' +
        'gold-set gap — auth-walled discovery reliability is UNMEASURED here, not 0.95+.',
    };
  }

  if (subset.length === 0) {
    return {
      adapterCount: requiresCustomerAuthAdapterCount,
      queryCount: 0,
      status: 'no-adapters-present',
      reason:
        `CHARIOT-SPEC §4.5 / AS §1.2a: the catalog carries ${requiresCustomerAuthAdapterCount} ` +
        'requiresCustomerAuth adapter(s), but the gold set labels NONE of their tools in ' +
        'relevantToolIds. This is a GOLD-SET-COVERAGE gap — the gold set must be extended with ' +
        'queries targeting this class before Recall@8 for it is measurable.',
    };
  }

  return {
    adapterCount: requiresCustomerAuthAdapterCount,
    queryCount: subset.length,
    status: 'measured',
    metrics: aggregate(subset, k, recallFloor),
  };
}
