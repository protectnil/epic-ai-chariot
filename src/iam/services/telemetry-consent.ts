/**
 * IAM — Operational Telemetry Consent Service
 *
 * Governing clause (traceability.spec_nodes, C4AMD::§8::6):
 *   "Consent state SHALL be tenant-scoped, auditable, versioned, and
 *   revocable."
 * Related (C4AMD::§8::4):
 *   "Customer authorization to use an adapter SHALL NOT imply telemetry
 *   permission."
 * Related (C4AMD::§8::2):
 *   "Operational telemetry SHALL be off by default."
 *
 * DESIGN — extends src/iam/services/audit.ts rather than a new store.
 * `audit.ts` already implements a per-tenant, append-only, monotonically-
 * sequenced event log (CAS-protected against concurrent writers, never
 * updated or deleted in place) — audited against
 * `src/iam/services/tenant.ts` (mutable, $set in place — wrong shape: a
 * consent write there would overwrite prior state, violating "versioned")
 * and `src/iam/services/scope-mapping-registry.ts` (also mutable
 * findOneAndUpdate-with-upsert — same problem). `audit.ts` is the only
 * existing per-tenant pattern whose writes are structurally insert-only,
 * so every consent change is appended there as one
 * `telemetry_consent_changed` event via `audit.log()`:
 *
 *   - tenant-scoped: `audit.log`/`audit.query`/`audit.queryLatest` are
 *     keyed by `tenantId` throughout — inherited for free.
 *   - versioned:     the event's own per-tenant `seq` (monotonic, CAS-
 *     protected in `audit.ts`'s `logImpl`) IS the consent version; every
 *     change produces a new, strictly-increasing seq. Nothing is ever
 *     mutated in place.
 *   - auditable:     `audit.query()` (via `getConsentHistory` below) and
 *     `audit.verifyChain()` already give full history + tamper-evidence
 *     for this event type with zero new storage code.
 *   - revocable:      `revokeConsent()` is `setConsent(..., false, ...)`
 *     — literally just another appended version. There is no delete path
 *     in this module, and `audit.ts`'s events collection is never
 *     targeted by an update/delete anywhere in this file.
 *
 * §8::4 (authorization SHALL NOT imply telemetry permission) is enforced
 * by CONSTRUCTION: `setConsent`/`revokeConsent` are this module's only
 * write entry points, and neither is called from any adapter-authorization
 * code path (`tenant.ts`, `oauth.ts`, `id-jag-*.ts`, `scim.ts` — grep
 * confirms zero cross-references). Telemetry consent has its own explicit
 * call sites; granting adapter access never touches this module. See
 * `telemetry-consent.test.ts`'s independence test.
 */

import * as audit from './audit.js';
import type { AuditEventType } from '../types.js';
import { hasMongoClient } from '../db.js';
import {
  localAppendConsent,
  localConsentHistory,
  localCurrentConsent,
  type LocalConsentRecord,
  type TelemetryTransport,
} from '../../observability/operational-telemetry/local-store.js';

export type { TelemetryTransport };

function fromLocal(tenantId: string, r: LocalConsentRecord): TelemetryConsentState {
  return {
    tenantId,
    version: r.version,
    enabled: r.enabled,
    transport: r.transport,
    changedAt: new Date(r.changedAt),
    changedBy: r.changedBy,
    statement: r.statement,
  };
}

function transportFromDetail(detail: Record<string, unknown> | undefined): TelemetryTransport {
  return detail?.['transport'] === 'auto' ? 'auto' : 'export-only';
}

/** The one audit event type this module ever appends. Not exported — callers use this module's own functions, never `audit.log` directly for consent. */
const TELEMETRY_CONSENT_EVENT: AuditEventType = 'telemetry_consent_changed';

export interface TelemetryConsentState {
  tenantId: string;
  /**
   * Monotonic per-tenant version number — the appending audit event's
   * `seq`. `0` is reserved for "no consent version has ever been recorded
   * for this tenant" (see `getCurrentConsent`); real versions start at 1.
   */
  version: number;
  enabled: boolean;
  /**
   * `auto` = a SEPARATE, versioned, revocable opt-in to automatic upload of
   * the closed-schema events to the license host (C4AMD §8 connected
   * deployments, amended 2026-10-12). `export-only` is the default and the
   * only value ever recorded alongside `enabled: false`.
   */
  transport: TelemetryTransport;
  changedAt: Date;
  changedBy: string;
  /** The operator's own words recorded with an enable (local store only); `null` when none was supplied. */
  statement: string | null;
}

export interface SetConsentOptions {
  transport?: TelemetryTransport;
  statement?: string;
}

function assertNonEmpty(value: string, field: string): void {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`telemetry-consent: ${field} must be a non-empty string`);
  }
}

/**
 * Append a new consent version. `enabled: true` grants operational
 * telemetry (C4AMD §8::2's "off by default" is the ABSENCE of any such
 * grant — see `getCurrentConsent`); `enabled: false` — including via
 * `revokeConsent` — revokes it. Always an insert (`audit.log`), never a
 * mutation of a prior version.
 */
export async function setConsent(
  tenantId: string,
  enabled: boolean,
  actorId: string,
  opts: SetConsentOptions = {},
): Promise<TelemetryConsentState> {
  assertNonEmpty(tenantId, 'tenantId');
  assertNonEmpty(actorId, 'actorId');

  // Transport is only meaningful alongside an enable; a revoke always
  // records `export-only` so a later re-enable cannot inherit `auto`.
  const transport: TelemetryTransport = enabled && opts.transport === 'auto' ? 'auto' : 'export-only';
  const statement = enabled && typeof opts.statement === 'string' && opts.statement.length > 0 ? opts.statement : null;

  if (!hasMongoClient()) {
    return fromLocal(tenantId, localAppendConsent(tenantId, { enabled, transport, changedBy: actorId, statement }));
  }

  const event = await audit.log(tenantId, TELEMETRY_CONSENT_EVENT, {
    actorId,
    targetType: 'tenant',
    targetId: tenantId,
    detail: { enabled, transport, ...(statement !== null ? { statement } : {}) },
  });

  return {
    tenantId,
    version: event.seq,
    enabled,
    transport,
    changedAt: event.timestamp,
    changedBy: actorId,
    statement,
  };
}

/**
 * Revoke telemetry consent for a tenant — always a NEW version with
 * `enabled: false`. Never deletes or mutates any prior consent record
 * (C4AMD §8::6's "revocable" is satisfied by appending, not erasing).
 */
export async function revokeConsent(tenantId: string, actorId: string): Promise<TelemetryConsentState> {
  return setConsent(tenantId, false, actorId);
}

/**
 * Current consent state = the latest `telemetry_consent_changed` event
 * for this tenant. A tenant with no consent history has never opted in —
 * telemetry is off by default (C4AMD §8::2) — represented as
 * `{ enabled: false, version: 0 }`, distinct from any real appended
 * version (which starts at 1), so a caller can tell "never granted" apart
 * from "granted once, at version 1."
 */
export async function getCurrentConsent(tenantId: string): Promise<TelemetryConsentState> {
  assertNonEmpty(tenantId, 'tenantId');

  if (!hasMongoClient()) {
    const local = localCurrentConsent(tenantId);
    if (!local) {
      return { tenantId, version: 0, enabled: false, transport: 'export-only', changedAt: new Date(0), changedBy: '', statement: null };
    }
    return fromLocal(tenantId, local);
  }

  const latest = await audit.queryLatest(tenantId, TELEMETRY_CONSENT_EVENT);
  if (!latest) {
    return { tenantId, version: 0, enabled: false, transport: 'export-only', changedAt: new Date(0), changedBy: '', statement: null };
  }
  const enabled = latest.detail?.['enabled'] === true;
  return {
    tenantId,
    version: latest.seq,
    enabled,
    transport: enabled ? transportFromDetail(latest.detail) : 'export-only',
    changedAt: latest.timestamp,
    changedBy: latest.actorId,
    statement: typeof latest.detail?.['statement'] === 'string' ? (latest.detail['statement'] as string) : null,
  };
}

/**
 * Full append-only consent history for a tenant, oldest version first —
 * every grant and revoke ever recorded. Directly satisfies the
 * "auditable" half of C4AMD §8::6: nothing here is ever deleted, so this
 * always returns the complete history, including revoked/superseded
 * versions.
 */
export async function getConsentHistory(tenantId: string): Promise<TelemetryConsentState[]> {
  assertNonEmpty(tenantId, 'tenantId');

  if (!hasMongoClient()) {
    return localConsentHistory(tenantId).map((r) => fromLocal(tenantId, r));
  }

  const { events } = await audit.query(tenantId, { eventType: TELEMETRY_CONSENT_EVENT, limit: 10_000 });
  return events.map((e) => {
    const enabled = e.detail?.['enabled'] === true;
    return {
      tenantId,
      version: e.seq,
      enabled,
      transport: enabled ? transportFromDetail(e.detail) : ('export-only' as TelemetryTransport),
      changedAt: e.timestamp,
      changedBy: e.actorId,
      statement: typeof e.detail?.['statement'] === 'string' ? (e.detail['statement'] as string) : null,
    };
  });
}
