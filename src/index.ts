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

// Chariot-specific: real-time anomaly detection + dispatch-layer wiring.
// reportToolDispatch() is the entry point the tool-dispatch layer calls
// per tool call to feed the detector (rate-spike, destructive-burst,
// cross-tenant-drift, and scope-violation rules); findings flow into the
// AlertQueue/ChariotEmitter above via anomalyAlertQueue/anomalyEmitter.
export {
  AnomalyDetector,
  ToolCallRateSpikeRule,
  DestructiveToolBurstRule,
  CrossTenantDriftRule,
  ScopeViolationRule,
  reportToolDispatch,
  anomalyDetector,
  anomalyAlertQueue,
  anomalyEmitter,
} from './observability/index.js';
export type {
  AnomalyRule,
  AnomalySignal,
  AnomalyFinding,
  AnomalySeverity,
  ToolDispatchReport,
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
