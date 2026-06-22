/**
 * Epic AI® Chariot
 *
 * The bundle: Chariot engine + IAM + Internal API Discovery + License validation.
 * Self-hosted. Your data never leaves.
 *
 * @module @epicai/chariot
 */

// Re-export everything from the Chariot engine
export * from './engine/index.js';

// Chariot-specific: IAM
export * as iam from './iam/index.js';

// Chariot-specific: License validation
export {
  validateLicense,
  revalidateLicense,
  checkSeatLimit,
  loadNativeBinding,
  requireNativeBinding,
  type LicenseInfo,
  type LicenseMode,
} from './license/index.js';

// Chariot-specific: Internal API Discovery
export { discover } from './discovery/index.js';

// Chariot-specific: AI-first observability
export { ChariotEmitter, ChariotMetrics, AlertQueue } from './observability/index.js';
export type {
  ChariotEvent,
  ChariotEventType,
  AlertSeverity,
  PendingAlert,
} from './observability/index.js';

// Chariot-specific: Adapter catalog trust & verification
export { VerifiedCatalog, DEFAULT_CATALOG_TRUST_CONFIG } from './catalog/index.js';
export type {
  AdapterVerificationRecord,
  CatalogTrustConfig,
  NormalizedAdapterMetadata,
  StaleDetectionConfig,
  TrustedAdapterEntry,
  VerificationStatus,
} from './catalog/index.js';
