/**
 * @epicai/chariot — Adapter Catalog Trust Types
 *
 * Verification status, stale detection, and metadata normalization
 * for Chariot adapter catalog entries.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { AdapterCatalogEntry, AdapterCategory } from '../engine/index.js';

// =============================================================================
// Verification
// =============================================================================

export type VerificationStatus = 'verified' | 'failed' | 'pending' | 'stale';

export interface AdapterVerificationRecord {
  /** Adapter name (matches AdapterCatalogEntry.name) */
  adapterName: string;
  /** Current verification status */
  status: VerificationStatus;
  /** ISO-8601 timestamp of the last successful or failed verification */
  lastVerifiedAt: string | null;
  /** Human-readable reason when status is 'failed' */
  verificationFailureReason: string | null;
  /** Number of consecutive verification failures */
  consecutiveFailures: number;
}

// =============================================================================
// Metadata normalization
// =============================================================================

export interface NormalizedAdapterMetadata {
  /** Canonical adapter name (lowercase, trimmed, hyphen-separated) */
  name: string;
  /** Display name (title-cased, trimmed) */
  displayName: string;
  /** Tool count derived from toolNames array length */
  toolCount: number;
  /** Category from the canonical set */
  category: AdapterCategory;
  /** Deduplicated, lowercased keyword set */
  keywords: string[];
  /** Framework label (e.g., 'mcp', 'rest', 'both') — inferred from catalog or registry */
  framework: 'mcp' | 'rest' | 'both' | 'unknown';
  /** Capability labels derived from keywords and tool names */
  capabilities: string[];
}

// =============================================================================
// Stale detection
// =============================================================================

export interface StaleDetectionConfig {
  /**
   * Maximum age in milliseconds before an adapter's verification is considered stale.
   * Default: 7 days (604_800_000 ms).
   */
  maxAgeMs: number;
}

// =============================================================================
// Combined trust entry
// =============================================================================

export interface TrustedAdapterEntry {
  /** Original Chariot catalog entry */
  catalogEntry: AdapterCatalogEntry;
  /** Verification record */
  verification: AdapterVerificationRecord;
  /** Normalized metadata */
  normalized: NormalizedAdapterMetadata;
}

// =============================================================================
// Catalog trust configuration
// =============================================================================

export interface CatalogTrustConfig {
  /** Stale detection settings */
  staleDetection: StaleDetectionConfig;
  /**
   * Whether to automatically mark adapters as stale during queries.
   * Default: true.
   */
  autoDetectStale: boolean;
}

export const DEFAULT_CATALOG_TRUST_CONFIG: CatalogTrustConfig = {
  staleDetection: {
    maxAgeMs: 7 * 24 * 60 * 60 * 1000, // 7 days
  },
  autoDetectStale: true,
};
