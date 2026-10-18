export { AnomalyDetector } from './Detector.js';
export {
  ToolCallRateSpikeRule,
  DestructiveToolBurstRule,
  CrossTenantDriftRule,
  ScopeViolationRule,
} from './rules.js';
export type {
  AnomalyRule,
  AnomalySignal,
  AnomalyFinding,
  AnomalySeverity,
} from './types.js';
export type { FindingCallback } from './Detector.js';
export type {
  RateSpikeOptions,
  DestructiveBurstOptions,
  CrossTenantDriftOptions,
} from './rules.js';
export {
  reportToolDispatch,
  anomalyDetector,
  anomalyAlertQueue,
  anomalyEmitter,
} from './wiring.js';
export type { ToolDispatchReport } from './wiring.js';
