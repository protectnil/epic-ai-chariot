/**
 * @epicai/chariot — Verified Catalog
 *
 * Trust layer over Chariot's adapter catalog. Adds:
 * - Per-adapter verification status (verified / failed / pending / stale)
 * - Stale detection based on configurable age threshold
 * - Metadata normalization (name, toolCount, keywords, capabilities)
 * - Deduplication of conflicting adapter entries
 * - Failure reason tracking
 *
 * Reads Chariot engine catalog entries and overlays trust metadata for
 * downstream consumers (routing, UI, audit).
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { AdapterCatalogEntry } from '../engine/index.js';
import type {
  AdapterVerificationRecord,
  CatalogTrustConfig,
  NormalizedAdapterMetadata,
  StaleDetectionConfig,
  TrustedAdapterEntry,
  VerificationStatus,
} from './types.js';
import { DEFAULT_CATALOG_TRUST_CONFIG } from './types.js';

// =============================================================================
// Normalization helpers
// =============================================================================

/** Lowercase, trim, collapse whitespace to hyphens */
export function canonicalName(raw: string): string {
  return raw.trim().toLowerCase().replace(/\s+/g, '-');
}

/** Title-case: first letter of each word uppercased */
function titleCase(raw: string): string {
  return raw
    .trim()
    .replace(/[-_]+/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

/** Deduplicate and lowercase an array of strings */
function dedupeKeywords(keywords: string[]): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const kw of keywords) {
    const lower = kw.trim().toLowerCase();
    if (lower && !seen.has(lower)) {
      seen.add(lower);
      result.push(lower);
    }
  }
  return result;
}

/**
 * Infer capability labels from keywords and tool names.
 * Maps common patterns to canonical capability labels.
 */
function inferCapabilities(keywords: string[], toolNames: string[]): string[] {
  const all = [...keywords, ...toolNames].map((s) => s.toLowerCase());
  const caps = new Set<string>();
  const patterns: [RegExp, string][] = [
    [/read|get|list|fetch|query|search/, 'read'],
    [/write|create|update|put|post|patch|delete|remove/, 'write'],
    [/auth|login|token|oauth|saml|sso/, 'auth'],
    [/monitor|alert|metric|log|trace|observe/, 'monitoring'],
    [/deploy|release|build|ci|cd|pipeline/, 'ci-cd'],
    [/encrypt|decrypt|vault|secret|credential/, 'security'],
    [/scan|vuln|cve|sast|dast|pentest/, 'scanning'],
    [/chat|message|notify|email|sms|slack/, 'messaging'],
  ];
  for (const token of all) {
    for (const [pattern, label] of patterns) {
      if (pattern.test(token)) {
        caps.add(label);
      }
    }
  }
  return [...caps].sort();
}

/**
 * ASCII byte-order comparison. Deterministic across locales/machines.
 * Returns negative if a < b, positive if a > b, 0 if equal.
 */
function asciiCompare(a: string, b: string): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const diff = a.charCodeAt(i) - b.charCodeAt(i);
    if (diff !== 0) return diff;
  }
  return a.length - b.length;
}

/**
 * Infer framework type from catalog entry.
 * Uses author and keyword heuristics since Chariot catalog entries
 * don't carry an explicit framework field.
 */
function inferFramework(entry: AdapterCatalogEntry): 'mcp' | 'rest' | 'both' | 'unknown' {
  const keywords = entry.keywords.map((k) => k.toLowerCase());
  const hasMcp = keywords.includes('mcp') || entry.author === 'vendor';
  const hasRest = keywords.includes('rest') || keywords.includes('rest-api');
  if (hasMcp && hasRest) return 'both';
  if (hasMcp) return 'mcp';
  if (hasRest) return 'rest';
  return 'unknown';
}

// =============================================================================
// VerifiedCatalog
// =============================================================================

export class VerifiedCatalog {
  private readonly verificationRecords = new Map<string, AdapterVerificationRecord>();
  private readonly config: CatalogTrustConfig;

  constructor(config?: Partial<CatalogTrustConfig>) {
    this.config = {
      ...DEFAULT_CATALOG_TRUST_CONFIG,
      ...config,
      staleDetection: {
        ...DEFAULT_CATALOG_TRUST_CONFIG.staleDetection,
        ...config?.staleDetection,
      },
    };
  }

  // ---------------------------------------------------------------------------
  // Canonical key — all verification lookups go through this
  // ---------------------------------------------------------------------------

  private verificationKey(adapterName: string): string {
    return canonicalName(adapterName);
  }

  // ---------------------------------------------------------------------------
  // Verification lifecycle
  // ---------------------------------------------------------------------------

  /**
   * Record a successful verification for an adapter.
   * @param adapterName - Adapter identifier
   * @param verifiedAt - Optional ISO-8601 timestamp override (defaults to now)
   */
  markVerified(adapterName: string, verifiedAt?: string): AdapterVerificationRecord {
    const key = this.verificationKey(adapterName);
    const record: AdapterVerificationRecord = {
      adapterName,
      status: 'verified',
      lastVerifiedAt: verifiedAt ?? new Date().toISOString(),
      verificationFailureReason: null,
      consecutiveFailures: 0,
    };
    this.verificationRecords.set(key, record);
    return record;
  }

  /**
   * Record a failed verification with a reason.
   */
  markFailed(adapterName: string, reason: string): AdapterVerificationRecord {
    const key = this.verificationKey(adapterName);
    const existing = this.verificationRecords.get(key);
    const record: AdapterVerificationRecord = {
      adapterName,
      status: 'failed',
      lastVerifiedAt: new Date().toISOString(),
      verificationFailureReason: reason,
      consecutiveFailures: (existing?.consecutiveFailures ?? 0) + 1,
    };
    this.verificationRecords.set(key, record);
    return record;
  }

  /**
   * Get the verification record for an adapter. Returns a 'pending' record
   * if no verification has been performed yet.
   */
  getVerification(adapterName: string): AdapterVerificationRecord {
    const key = this.verificationKey(adapterName);
    const record = this.verificationRecords.get(key);
    if (record) {
      // Auto-detect stale
      if (this.config.autoDetectStale && record.status === 'verified' && record.lastVerifiedAt) {
        if (this.isStaleTimestamp(record.lastVerifiedAt)) {
          return { ...record, status: 'stale' };
        }
      }
      return record;
    }
    return {
      adapterName,
      status: 'pending',
      lastVerifiedAt: null,
      verificationFailureReason: null,
      consecutiveFailures: 0,
    };
  }

  /**
   * Get all verification records.
   */
  allVerifications(): AdapterVerificationRecord[] {
    return [...this.verificationRecords.values()].map((r) => {
      if (this.config.autoDetectStale && r.status === 'verified' && r.lastVerifiedAt) {
        if (this.isStaleTimestamp(r.lastVerifiedAt)) {
          return { ...r, status: 'stale' as VerificationStatus };
        }
      }
      return r;
    });
  }

  // ---------------------------------------------------------------------------
  // Stale detection
  // ---------------------------------------------------------------------------

  get staleDetection(): StaleDetectionConfig {
    return this.config.staleDetection;
  }

  /**
   * Check if a timestamp is stale relative to the configured threshold.
   */
  isStaleTimestamp(isoTimestamp: string): boolean {
    const age = Date.now() - new Date(isoTimestamp).getTime();
    return age > this.config.staleDetection.maxAgeMs;
  }

  /**
   * Return all adapters whose verification is stale.
   */
  staleAdapters(): AdapterVerificationRecord[] {
    const results: AdapterVerificationRecord[] = [];
    for (const record of this.verificationRecords.values()) {
      if (record.status === 'verified' && record.lastVerifiedAt) {
        if (this.isStaleTimestamp(record.lastVerifiedAt)) {
          results.push({ ...record, status: 'stale' });
        }
      }
    }
    return results;
  }

  /**
   * Return all adapters whose verification has failed.
   */
  failedAdapters(): AdapterVerificationRecord[] {
    return [...this.verificationRecords.values()].filter((r) => r.status === 'failed');
  }

  // ---------------------------------------------------------------------------
  // Metadata normalization
  // ---------------------------------------------------------------------------

  /**
   * Normalize a catalog entry's metadata for consistency.
   */
  normalize(entry: AdapterCatalogEntry): NormalizedAdapterMetadata {
    return {
      name: canonicalName(entry.name),
      displayName: entry.displayName?.trim() || titleCase(entry.name),
      toolCount: entry.toolNames.length,
      category: entry.category,
      keywords: dedupeKeywords(entry.keywords),
      framework: inferFramework(entry),
      capabilities: inferCapabilities(entry.keywords, entry.toolNames),
    };
  }

  // ---------------------------------------------------------------------------
  // Deduplication
  // ---------------------------------------------------------------------------

  /**
   * Deduplicate adapter entries by canonical name.
   * When duplicates are found, the entry with the higher version wins.
   * Revoked entries are always discarded in favor of non-revoked ones.
   */
  deduplicate(entries: AdapterCatalogEntry[]): AdapterCatalogEntry[] {
    const byCanonical = new Map<string, AdapterCatalogEntry>();
    for (const entry of entries) {
      const key = canonicalName(entry.name);
      const existing = byCanonical.get(key);
      if (!existing) {
        byCanonical.set(key, entry);
        continue;
      }
      // Prefer non-revoked
      if (existing.revoked && !entry.revoked) {
        byCanonical.set(key, entry);
        continue;
      }
      if (!existing.revoked && entry.revoked) {
        continue;
      }
      // Both same revocation state — prefer higher version
      if (this.compareVersions(entry.version, existing.version) > 0) {
        byCanonical.set(key, entry);
      }
    }
    return [...byCanonical.values()];
  }

  /**
   * Semver-spec comparison (semver.org §11).
   * Returns positive if a > b, negative if a < b, 0 if equal.
   *
   * - Strips leading 'v' and build metadata (+...).
   * - Compares core (major.minor.patch) numerically.
   * - A release (no prerelease) beats the same core with a prerelease tag.
   * - Prerelease identifiers compared per spec: numeric < alpha, numeric by
   *   value, alpha lexically (ASCII), longer prerelease set wins if all
   *   preceding identifiers are equal.
   * - Falls back to localeCompare with numeric option for unparseable input.
   */
  private compareVersions(a: string, b: string): number {
    const parse = (v: string) => {
      const stripped = v.trim().replace(/^v/i, '');
      // Remove build metadata (everything after +)
      const noBuild = stripped.split('+')[0];
      const dashIdx = noBuild.indexOf('-');
      const core = dashIdx === -1 ? noBuild : noBuild.slice(0, dashIdx);
      const prerelease = dashIdx === -1 ? null : noBuild.slice(dashIdx + 1);
      const segments = core.split('.').map(Number);
      // If any segment is NaN, mark as unparseable
      const valid = segments.every((n) => Number.isFinite(n));
      return { segments, prerelease, valid, raw: stripped };
    };

    const pa = parse(a);
    const pb = parse(b);

    // If either is unparseable, fall back to ASCII byte-order comparison
    // (locale-independent, deterministic across machines per semver spec)
    if (!pa.valid || !pb.valid) {
      return asciiCompare(pa.raw, pb.raw);
    }

    // Compare core segments numerically
    const maxLen = Math.max(pa.segments.length, pb.segments.length);
    for (let i = 0; i < maxLen; i++) {
      const va = pa.segments[i] ?? 0;
      const vb = pb.segments[i] ?? 0;
      if (va !== vb) return va - vb;
    }

    // Equal core: release (no prerelease) > prerelease
    if (pa.prerelease === null && pb.prerelease === null) return 0;
    if (pa.prerelease === null) return 1;   // a is release, b is prerelease
    if (pb.prerelease === null) return -1;  // b is release, a is prerelease

    // Both have prerelease — compare dot-separated identifiers per semver §11.4
    const aIds = pa.prerelease.split('.');
    const bIds = pb.prerelease.split('.');
    const len = Math.max(aIds.length, bIds.length);
    for (let i = 0; i < len; i++) {
      // Shorter set loses if all preceding identifiers are equal
      if (i >= aIds.length) return -1;
      if (i >= bIds.length) return 1;

      const aNum = /^\d+$/.test(aIds[i]) ? Number(aIds[i]) : null;
      const bNum = /^\d+$/.test(bIds[i]) ? Number(bIds[i]) : null;

      // Numeric identifiers always have lower precedence than non-numeric
      if (aNum !== null && bNum !== null) {
        if (aNum !== bNum) return aNum - bNum;
      } else if (aNum !== null) {
        return -1; // numeric < alpha
      } else if (bNum !== null) {
        return 1;  // alpha > numeric
      } else {
        // Both alpha — compare by ASCII code point (locale-independent)
        const cmp = asciiCompare(aIds[i], bIds[i]);
        if (cmp !== 0) return cmp;
      }
    }
    return 0;
  }

  // ---------------------------------------------------------------------------
  // Combined trust view
  // ---------------------------------------------------------------------------

  /**
   * Build a full trust view for a set of catalog entries.
   * Deduplicates, normalizes, and attaches verification records.
   */
  buildTrustView(entries: AdapterCatalogEntry[]): TrustedAdapterEntry[] {
    const deduped = this.deduplicate(entries);
    return deduped.map((entry) => ({
      catalogEntry: entry,
      verification: this.getVerification(entry.name),
      normalized: this.normalize(entry),
    }));
  }

  /**
   * Filter a trust view to only verified (non-stale, non-failed) adapters.
   */
  verifiedOnly(entries: TrustedAdapterEntry[]): TrustedAdapterEntry[] {
    return entries.filter((e) => e.verification.status === 'verified');
  }

  /**
   * Total number of verification records stored.
   */
  get size(): number {
    return this.verificationRecords.size;
  }

  /**
   * Clear all verification records.
   */
  clear(): void {
    this.verificationRecords.clear();
  }
}
