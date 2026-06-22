/**
 * @epicai/chariot — Catalog Trust Module
 *
 * Adapter verification, stale detection, deduplication, and metadata normalization.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

export { VerifiedCatalog, canonicalName } from './VerifiedCatalog.js';
export {
  applyChariotCatalogEnv,
  chariotBundlePath,
  chariotCatalogEnv,
  chariotCatalogPath,
  loadChariotAdapterCatalog,
  loadChariotMcpRegistry,
  type ChariotRegistryEntry,
} from './artifacts.js';
export {
  TenantDemotionOverrideStore,
  MAX_OVERRIDE_DURATION_MS,
  MIN_JUSTIFICATION_LENGTH,
  type TenantDemotionOverride,
  type IssueOverrideInputs,
} from './TenantDemotionOverrides.js';
export type {
  AdapterVerificationRecord,
  CatalogTrustConfig,
  NormalizedAdapterMetadata,
  StaleDetectionConfig,
  TrustedAdapterEntry,
  VerificationStatus,
} from './types.js';
export { DEFAULT_CATALOG_TRUST_CONFIG } from './types.js';
