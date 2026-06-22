/**
 * CLI-output formatting helpers for `chariot license status` and
 * `chariot license renew-now`. Pure (no I/O, no console) so the CLI
 * shell composes the output and tests can assert against the lines
 * directly without spawning the binary.
 */

import type { LicenseInfo } from './loader.js';
import type { RenewOutcome } from './renew-client.js';

export interface LastRenewalRecord {
  ts: number;
  outcome_kind: string;
  message?: string;
}

/**
 * Whole-day delta between now and an ISO date (YYYY-MM-DD). Positive
 * when the date is in the future, zero on the same day, negative when
 * past. Returns null on unparseable input.
 */
export function daysRemainingFromIso(
  expiresAtIso: string | undefined,
  now: number = Date.now(),
): number | null {
  if (!expiresAtIso) return null;
  const exp = Date.parse(expiresAtIso);
  if (!Number.isFinite(exp)) return null;
  return Math.floor((exp - now) / 86400000);
}

function pluralDays(n: number): string {
  return `${n} day${n === 1 ? '' : 's'}`;
}

/**
 * Build the lines `chariot license status` prints, by mode. Returns
 * plain strings — the CLI shell colorizes per the LicenseInfo mode.
 * `now` injectable for tests.
 */
export function formatStatusLines(
  license: LicenseInfo,
  lastRenewal: LastRenewalRecord | null,
  now: number = Date.now(),
): string[] {
  const lines: string[] = [];
  switch (license.mode) {
    case 'licensed': {
      const days = daysRemainingFromIso(license.expiresAt, now);
      lines.push('License Details');
      if (license.companyName) lines.push(`Company: ${license.companyName}`);
      if (license.companyId) lines.push(`Company ID: ${license.companyId}`);
      if (license.totalSeats !== undefined)
        lines.push(`Seats: ${license.totalSeats}`);
      if (license.issuedAt) lines.push(`Issued: ${license.issuedAt}`);
      lines.push(
        `Expires: ${license.expiresAt}` +
          (days !== null ? ` (${pluralDays(days)} remaining)` : ''),
      );
      lines.push('Status: Valid');
      break;
    }
    case 'grace': {
      const days = daysRemainingFromIso(license.expiresAt, now);
      const graceDays = daysRemainingFromIso(license.graceEndsAt, now);
      lines.push('License — Grace Period');
      if (license.companyName) lines.push(`Company: ${license.companyName}`);
      if (license.totalSeats !== undefined)
        lines.push(`Seats: ${license.totalSeats}`);
      lines.push(
        `Expired: ${license.expiresAt}` +
          (days !== null ? ` (${pluralDays(Math.abs(days))} ago)` : ''),
      );
      lines.push(
        `Grace ends: ${license.graceEndsAt}` +
          (graceDays !== null && graceDays >= 0
            ? ` (${pluralDays(graceDays)} remaining)`
            : ''),
      );
      lines.push(
        'Status: Expired — full access continues during grace period',
      );
      break;
    }
    case 'degraded': {
      const days = daysRemainingFromIso(license.expiresAt, now);
      lines.push('License — Lapsed');
      if (license.companyName) lines.push(`Company: ${license.companyName}`);
      lines.push(
        `Expired: ${license.expiresAt}` +
          (days !== null ? ` (${pluralDays(Math.abs(days))} ago)` : ''),
      );
      lines.push('Status: Multi-user features paused');
      break;
    }
    default:
      lines.push('No license file');
      if (license.reason) lines.push(`Reason: ${license.reason}`);
  }
  if (lastRenewal) {
    lines.push(`Last renewal attempt: ${new Date(lastRenewal.ts * 1000).toISOString()}`);
    lines.push(`Outcome: ${lastRenewal.outcome_kind}`);
    if (lastRenewal.message) {
      lines.push(`Detail: ${lastRenewal.message}`);
    }
  }
  return lines;
}

export interface RenewSummary {
  /** Single-line human-readable summary. */
  line: string;
  /** Hint to the CLI shell on color: g=green, y=yellow, r=red. */
  color: 'g' | 'y' | 'r';
  /** HTTP status, or 0 for outcomes that never reached a server response. */
  status: number;
  /** Whether a new license file was written to disk. */
  wrote: boolean;
}

export function summarizeRenewOutcome(o: RenewOutcome): RenewSummary {
  switch (o.kind) {
    case 'renewed':
      return {
        line: `License renewed — new expiry ${o.claims.expiresAtIso}`,
        color: 'g',
        status: o.status,
        wrote: true,
      };
    case 'no_new_billing':
      return {
        line: 'No new billing yet — current license unchanged.',
        color: 'y',
        status: o.status,
        wrote: false,
      };
    case 'unauthorized':
      return {
        line: `Auth failed (replay, stale ts, or proof mismatch): ${o.message}`,
        color: 'r',
        status: o.status,
        wrote: false,
      };
    case 'unknown_company':
      return {
        line: `Server does not know this company_id: ${o.message}`,
        color: 'r',
        status: o.status,
        wrote: false,
      };
    case 'jwt_stale':
      return {
        line: `Local JWT is stale — re-download from the portal: ${o.message}`,
        color: 'r',
        status: o.status,
        wrote: false,
      };
    case 'no_local_license':
      return { line: o.message, color: 'r', status: 0, wrote: false };
    case 'server_error':
      return {
        line: `Server error: ${o.message}`,
        color: 'r',
        status: o.status,
        wrote: false,
      };
    case 'network_error':
      return {
        line: `Network error: ${o.message}`,
        color: 'r',
        status: 0,
        wrote: false,
      };
    case 'invalid_response':
      return {
        line: `Invalid server response: ${o.message}`,
        color: 'r',
        status: o.status,
        wrote: false,
      };
  }
}

/**
 * The "HTTP NNN · license file updated/not updated" line that follows
 * the summary in `chariot license renew-now` per spec §10.3.
 */
export function formatRenewStatusLine(s: RenewSummary): string {
  const statusLabel = s.status > 0 ? `HTTP ${s.status}` : 'no HTTP response';
  return `${statusLabel} · license file ${s.wrote ? 'updated' : 'not updated'}`;
}
